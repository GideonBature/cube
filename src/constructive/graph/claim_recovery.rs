//! The `Recovery` role: spending a claim without the Engine.
//!
//! A claim output has no key path. Its only spend is the single tapscript leaf
//! `<statement digest> OP_DROP <beneficiary key> OP_CHECKSIG`, and a [`ClaimRecoveryPackage`]
//! carries that script and its control block. This module turns the package into one transaction:
//!
//! ```text
//! input  0: the claim outpoint, script path, witness = [signature, claim_script, control_block]
//! output 0: the destination the caller names
//! ```
//!
//! # The rule this module enforces
//!
//! [`ClaimRecovery::verify`] takes the transaction, not a descriptor built by the caller, and
//! re-derives everything from the package and the claim prevout. A beneficiary who runs it cannot be
//! talked into a spend that pays a different destination, claims a different outpoint, spends a
//! different claim script, or leaves a miner fee outside the accepted range. That matters because a
//! recovery helper is exactly the kind of party that could hand over a plausible-looking transaction
//! with the beneficiary's coins going elsewhere.
//!
//! # What this module does not enforce
//!
//! - **Expiry.** The package records `expiry_height`, but a transaction has no notion of "too late".
//!   Refusing a stale claim is the client's policy, not a consensus rule.
//! - **Fee policy.** The miner fee is whatever the claim value leaves after the output, and
//!   [`FeeBounds`] only checks the range the caller accepts. Deriving it from the package's
//!   `fee_rate_sat_per_vb` and the transaction's vsize is the caller's job.
//! - **The beneficiary's key.** No secret is touched here. The caller signs the hash returned by
//!   [`ClaimRecovery::signing_hash`] and installs the witness with [`ClaimRecovery::witness`].
//! - **Chain state.** Nothing here reads a chain or knows whether the claim is already spent.
//!   Recovering a spent claim is rejected by consensus, not by this module.

use crate::constructive::contracts::fixed_split_vault_v1::recovery_package::{
    ClaimRecoveryPackage, DischargeState, PackageError,
};
use crate::constructive::graph::successor_funding::FeeBounds;
use crate::constructive::taproot::hash_tap_leaf;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

/// The input sequence the recovery spend commits to.
///
/// Opt-in RBF so a stuck recovery can be fee-bumped. It is part of every signature over the
/// transaction, so changing it changes what the beneficiary authorised.
pub const RECOVERY_INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// One claim recovery spend, fully specified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRecovery {
    claim_outpoint: OutPoint,
    claim_scriptpubkey: ScriptBuf,
    claim_script: Vec<u8>,
    control_block: Vec<u8>,
    destination_script: ScriptBuf,
    entitlement_sats: u64,
    fee_sats: u64,
}

impl ClaimRecovery {
    /// Builds the recovery spend of `package` to `destination_script`, paying `fee_sats`.
    ///
    /// `claim_prevout` is the output the claim outpoint refers to: its script must be the package's
    /// claim script and its value must be the package's entitlement.
    pub fn new(
        package: &ClaimRecoveryPackage,
        claim_prevout: &TxOut,
        destination_script: ScriptBuf,
        fee_sats: u64,
    ) -> Result<Self, ClaimRecoveryError> {
        // 1 The package must describe a live claim.
        package
            .validate()
            .map_err(ClaimRecoveryError::PackageInvalid)?;
        if package.discharge == DischargeState::Discharged {
            return Err(ClaimRecoveryError::ClaimDischarged);
        }
        let anchor = package
            .claim_outpoint
            .ok_or(ClaimRecoveryError::MissingClaimOutpoint)?;

        // 2 The prevout must be this claim, and worth exactly what the package says it is worth.
        let claim_scriptpubkey = package
            .claim_scriptpubkey()
            .ok_or(ClaimRecoveryError::ClaimScriptMismatch)?;
        if claim_prevout.script_pubkey != ScriptBuf::from_bytes(claim_scriptpubkey.clone()) {
            return Err(ClaimRecoveryError::ClaimScriptMismatch);
        }
        let claim_value_sats = claim_prevout.value.to_sat();
        if claim_value_sats != package.entitlement_sats {
            return Err(ClaimRecoveryError::EntitlementMismatch {
                package_sats: package.entitlement_sats,
                claim_sats: claim_value_sats,
            });
        }

        // 3 The fee cannot consume the claim.
        if fee_sats >= claim_value_sats {
            return Err(ClaimRecoveryError::FeeExceedsValue {
                value_sats: claim_value_sats,
                fee_sats,
            });
        }

        Ok(Self {
            claim_outpoint: OutPoint {
                txid: Txid::from_byte_array(anchor.txid),
                vout: anchor.vout,
            },
            claim_scriptpubkey: ScriptBuf::from_bytes(claim_scriptpubkey),
            claim_script: package.claim_script.clone(),
            control_block: package.control_block.clone(),
            destination_script,
            entitlement_sats: claim_value_sats,
            fee_sats,
        })
    }

    /// The claim outpoint being spent.
    pub fn claim_outpoint(&self) -> OutPoint {
        self.claim_outpoint
    }

    /// The destination the recovery pays.
    pub fn destination_script(&self) -> &ScriptBuf {
        &self.destination_script
    }

    /// The miner fee this recovery leaves.
    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    /// The value the destination receives.
    pub fn output_value_sats(&self) -> u64 {
        self.entitlement_sats - self.fee_sats
    }

    /// Builds the unsigned transaction: one claim input, one destination output.
    ///
    /// The witness is empty until the caller signs; [`Self::witness`] installs it.
    pub fn transaction(&self) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: self.claim_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: RECOVERY_INPUT_SEQUENCE,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(self.output_value_sats()),
                script_pubkey: self.destination_script.clone(),
            }],
        }
    }

    /// Returns the BIP-341 script-path sighash the beneficiary must sign.
    ///
    /// The leaf is the package's claim script at leaf version `0xc0` and there is no code
    /// separator, so the position is `0xffff_ffff`.
    pub fn signing_hash(&self, claim_prevout: &TxOut) -> Result<[u8; 32], ClaimRecoveryError> {
        if claim_prevout.script_pubkey != self.claim_scriptpubkey {
            return Err(ClaimRecoveryError::ClaimScriptMismatch);
        }

        let leaf_hash = TapLeafHash::from_byte_array(hash_tap_leaf(&self.claim_script, 0xc0));
        let sighash = SighashCache::new(self.transaction())
            .taproot_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(claim_prevout)),
                None,
                Some((leaf_hash, 0xffff_ffff)),
                TapSighashType::Default,
            )
            .map_err(|_| ClaimRecoveryError::SighashFailed)?;

        Ok(sighash.to_byte_array())
    }

    /// Assembles the script-path witness in the order the claim script expects.
    pub fn witness(&self, signature: [u8; 64]) -> Witness {
        Witness::from_slice(&[
            signature.to_vec(),
            self.claim_script.clone(),
            self.control_block.clone(),
        ])
    }

    /// Verifies an unsigned recovery transaction against the package and the claim prevout.
    ///
    /// Returns the descriptor the transaction authorises. A helper that hands over a transaction
    /// paying itself, claiming another outpoint, or paying an absurd fee is rejected here.
    pub fn verify(
        transaction: &Transaction,
        package: &ClaimRecoveryPackage,
        claim_prevout: &TxOut,
        destination_script: &ScriptBuf,
        bounds: FeeBounds,
    ) -> Result<Self, ClaimRecoveryError> {
        // 1 Shape: version, locktime, one input, one output, and still unsigned.
        if transaction.version != Version::TWO
            || transaction.lock_time != LockTime::ZERO
            || transaction.input.len() != 1
            || transaction.output.len() != 1
        {
            return Err(ClaimRecoveryError::TransactionShapeMismatch);
        }
        if !transaction.input[0].witness.is_empty() {
            return Err(ClaimRecoveryError::TransactionShapeMismatch);
        }

        // 2 The input must be the package's claim with the committed sequence.
        let anchor = package
            .claim_outpoint
            .ok_or(ClaimRecoveryError::MissingClaimOutpoint)?;
        let expected_outpoint = OutPoint {
            txid: Txid::from_byte_array(anchor.txid),
            vout: anchor.vout,
        };
        if transaction.input[0].previous_output != expected_outpoint
            || transaction.input[0].sequence != RECOVERY_INPUT_SEQUENCE
        {
            return Err(ClaimRecoveryError::TransactionInputMismatch);
        }

        // 3 The output must pay the destination the caller named.
        let output = &transaction.output[0];
        if output.script_pubkey != *destination_script {
            return Err(ClaimRecoveryError::DestinationMismatch);
        }

        // 4 The fee is whatever the claim leaves, and it has to be acceptable. Rebuilding through
        //   `new` re-checks the package, the prevout script and the entitlement.
        let fee_sats = claim_prevout
            .value
            .to_sat()
            .checked_sub(output.value.to_sat())
            .ok_or(ClaimRecoveryError::OutputExceedsClaim {
                claim_sats: claim_prevout.value.to_sat(),
                output_sats: output.value.to_sat(),
            })?;
        if !bounds.contains(fee_sats) {
            return Err(ClaimRecoveryError::MinerFeeOutOfBounds {
                fee_sats,
                min_sats: bounds.min_sats,
                max_sats: bounds.max_sats,
            });
        }

        ClaimRecovery::new(package, claim_prevout, destination_script.clone(), fee_sats)
    }
}

/// Rejection reasons for a claim recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimRecoveryError {
    /// The recovery package is not internally consistent.
    PackageInvalid(PackageError),
    /// The package records the claim as already spent.
    ClaimDischarged,
    /// The package does not carry the claim outpoint.
    MissingClaimOutpoint,
    /// The prevout is not the claim the package describes.
    ClaimScriptMismatch,
    /// The prevout value and the package entitlement disagree.
    EntitlementMismatch {
        /// The value the package records.
        package_sats: u64,
        /// The value the prevout actually holds.
        claim_sats: u64,
    },
    /// The requested fee consumes the whole claim.
    FeeExceedsValue {
        /// The claim value.
        value_sats: u64,
        /// The requested fee.
        fee_sats: u64,
    },
    /// The transaction's version, locktime, input/output count or witness state is wrong.
    TransactionShapeMismatch,
    /// The transaction spends something other than the claim, or changes its sequence.
    TransactionInputMismatch,
    /// The single output does not pay the destination the caller named.
    DestinationMismatch,
    /// The output is worth more than the claim.
    OutputExceedsClaim {
        /// The claim value.
        claim_sats: u64,
        /// The output value.
        output_sats: u64,
    },
    /// The miner fee lies outside the range the caller accepts.
    MinerFeeOutOfBounds {
        /// The fee the transaction leaves.
        fee_sats: u64,
        /// The smallest accepted fee.
        min_sats: u64,
        /// The largest accepted fee.
        max_sats: u64,
    },
    /// The sighash could not be computed.
    SighashFailed,
}
