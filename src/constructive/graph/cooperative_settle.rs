//! The `CooperativeSettle` edge: a whole claim tree exits in one transaction.
//!
//! `SuccessorFunding` turns a deposit into separate beneficiary claims. A single beneficiary can
//! already recover with [`crate::constructive::graph::claim_recovery::ClaimRecovery`]; that path
//! deliberately knows nothing about the other claims. `CooperativeSettle` is the other shape: every
//! beneficiary claim is spent in **one** transaction, in manifest order, and each is paid its full
//! entitlement to a destination the beneficiary authorised by signing the same sighash.
//!
//! ```text
//! input  0..n: the beneficiary claims, recovery leaf, one signature per claim
//! input  n:    the fee input (its whole value is the miner fee; no output)
//! output 0..n: one native output per beneficiary, exact entitlement, in manifest order
//! ```
//!
//! # The rule this module enforces
//!
//! [`CooperativeSettle::verify`] takes the transaction and the packages, not a descriptor built by
//! the caller, and re-derives every input, output and amount from the manifest. The package set
//! must cover every beneficiary allocation exactly once. A settlement that omits a beneficiary,
//! pays one twice, redirects an amount, swaps recipients, spends another statement's claim or
//! leaves a fee outside the accepted range is rejected. Because the transaction spends **every**
//! claim, no beneficiary is erased while another exits (INV-12), and no claim remains for a second
//! settlement.
//!
//! # What this module does not enforce
//!
//! - **The fee input's script and signature.** The fee input is an ordinary UTXO owned by the
//!   coordinator; its script is not in the manifest, and its signature is checked by Bitcoin. The
//!   module records its prevout and requires its whole value to be the miner fee.
//! - **The execution fee.** The `ExecutionFee` payout was funded by `SuccessorFunding` and is not
//!   part of the claim tree. Paying it again here would double-pay it, so the package set covers
//!   only beneficiary allocations.
//! - **Expiry.** The packages carry `expiry_height`, but a transaction has no notion of "too late".
//! - **Signing.** No key material is touched. [`CooperativeSettle::claim_signing_hash`] returns the
//!   digest each beneficiary signs; [`CooperativeSettle::claim_witness`] installs it.

use crate::constructive::contracts::fixed_split_vault_v1::recovery_package::{
    ClaimRecoveryPackage, PackageError,
};
use crate::constructive::graph::successor_funding::FeeBounds;
use crate::constructive::taproot::hash_tap_leaf;
use crate::model::fixed_split_vault_v1::manifest::{ManifestError, PayoutKind, TransitionManifest};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// The input sequence every input of a cooperative settlement commits to.
///
/// Opt-in RBF so a stuck settlement can be fee-bumped, and no relative locktime. The fee input's
/// owner signs the same sequence; changing it changes what every signer authorised.
pub const SETTLE_INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// A fully specified cooperative settlement of one claim tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CooperativeSettle {
    statement_digest: [u8; 32],
    packages: Vec<ClaimRecoveryPackage>,
    destinations: Vec<ScriptBuf>,
    fee_input: OutPoint,
    fee_prevout: TxOut,
    transaction: Transaction,
}

impl CooperativeSettle {
    /// Builds a settlement of every beneficiary claim in `packages`.
    ///
    /// `packages` must contain exactly one package per beneficiary allocation, in manifest order,
    /// and `destinations` must be the matching destinations in the same order. `fee_input` is an
    /// ordinary UTXO whose whole value becomes the miner fee; it must not be one of the claims.
    pub fn new(
        manifest: &TransitionManifest,
        packages: &[ClaimRecoveryPackage],
        destinations: Vec<ScriptBuf>,
        fee_input: OutPoint,
        fee_prevout: &TxOut,
        bounds: FeeBounds,
    ) -> Result<Self, CooperativeSettleError> {
        Self::build_and_validate(
            manifest,
            packages,
            &destinations,
            fee_input,
            fee_prevout,
            bounds,
        )
    }

    /// Verifies a settlement transaction against the manifest, the packages and a fee range.
    pub fn verify(
        transaction: &Transaction,
        manifest: &TransitionManifest,
        packages: &[ClaimRecoveryPackage],
        destinations: &[ScriptBuf],
        fee_input: OutPoint,
        fee_prevout: &TxOut,
        bounds: FeeBounds,
    ) -> Result<Self, CooperativeSettleError> {
        let claim_count = packages.len();
        if destinations.len() != claim_count {
            return Err(CooperativeSettleError::DestinationCountMismatch {
                expected: claim_count,
                found: destinations.len(),
            });
        }
        if transaction.version != Version::TWO
            || transaction.lock_time != LockTime::ZERO
            || transaction.input.len() != claim_count + 1
            || transaction.output.len() != claim_count
        {
            return Err(CooperativeSettleError::TransactionShapeMismatch);
        }

        for (index, package) in packages.iter().enumerate() {
            let anchor = package
                .claim_outpoint
                .ok_or(CooperativeSettleError::MissingClaimOutpoint { index })?;
            let expected_outpoint = OutPoint {
                txid: bitcoin::Txid::from_byte_array(anchor.txid),
                vout: anchor.vout,
            };
            if transaction.input[index].previous_output != expected_outpoint
                || transaction.input[index].sequence != SETTLE_INPUT_SEQUENCE
            {
                return Err(CooperativeSettleError::TransactionInputMismatch { index });
            }
            let output = &transaction.output[index];
            if output.value.to_sat() != package.entitlement_sats
                || output.script_pubkey != destinations[index]
            {
                return Err(CooperativeSettleError::TransactionOutputMismatch { index });
            }
        }
        if transaction.input[claim_count].previous_output != fee_input
            || transaction.input[claim_count].sequence != SETTLE_INPUT_SEQUENCE
        {
            return Err(CooperativeSettleError::FeeInputMismatch);
        }

        // Rebuilding re-checks the package set, statement, beneficiaries, values and fee.
        let built = Self::build_and_validate(
            manifest,
            packages,
            destinations,
            fee_input,
            fee_prevout,
            bounds,
        )?;
        if built.transaction != *transaction {
            return Err(CooperativeSettleError::TransactionShapeMismatch);
        }
        Ok(built)
    }

    /// Validates the plan and builds the one transaction every signer sees.
    fn build_and_validate(
        manifest: &TransitionManifest,
        packages: &[ClaimRecoveryPackage],
        destinations: &[ScriptBuf],
        fee_input: OutPoint,
        fee_prevout: &TxOut,
        bounds: FeeBounds,
    ) -> Result<Self, CooperativeSettleError> {
        manifest
            .validate()
            .map_err(CooperativeSettleError::ManifestInvalid)?;
        let statement_digest = manifest.statement_digest();

        // 1 The package set must cover every beneficiary allocation exactly once, in order.
        let beneficiary_payouts: Vec<_> = manifest
            .payouts
            .iter()
            .filter(|payout| payout.kind == PayoutKind::BeneficiaryAllocation)
            .collect();
        if beneficiary_payouts.is_empty() {
            return Err(CooperativeSettleError::NoBeneficiaryClaims);
        }
        if packages.len() != beneficiary_payouts.len() {
            return Err(CooperativeSettleError::ClaimCountMismatch {
                expected: beneficiary_payouts.len(),
                found: packages.len(),
            });
        }
        if destinations.len() != packages.len() {
            return Err(CooperativeSettleError::DestinationCountMismatch {
                expected: packages.len(),
                found: destinations.len(),
            });
        }

        let mut claim_outpoints = Vec::with_capacity(packages.len());
        for (index, (package, payout)) in packages.iter().zip(&beneficiary_payouts).enumerate() {
            package
                .validate()
                .map_err(CooperativeSettleError::PackageInvalid)?;
            if !package.is_recoverable() {
                return Err(CooperativeSettleError::ClaimNotRecoverable { index });
            }
            if package.statement_digest != statement_digest {
                return Err(CooperativeSettleError::StatementMismatch { index });
            }
            if package.beneficiary_key != payout.recipient_key {
                return Err(CooperativeSettleError::BeneficiaryMismatch { index });
            }
            if package.entitlement_sats != payout.amount_sats {
                return Err(CooperativeSettleError::EntitlementMismatch {
                    index,
                    manifest_sats: payout.amount_sats,
                    package_sats: package.entitlement_sats,
                });
            }
            let anchor = package
                .claim_outpoint
                .ok_or(CooperativeSettleError::MissingClaimOutpoint { index })?;
            let outpoint = OutPoint {
                txid: bitcoin::Txid::from_byte_array(anchor.txid),
                vout: anchor.vout,
            };
            if outpoint == fee_input {
                return Err(CooperativeSettleError::FeeInputConflictsWithClaim { index });
            }
            if claim_outpoints.contains(&outpoint) {
                return Err(CooperativeSettleError::RepeatedClaimOutpoint { index });
            }
            if destinations[index].as_bytes().is_empty() {
                return Err(CooperativeSettleError::EmptyDestination { index });
            }
            claim_outpoints.push(outpoint);
        }

        // 2 The fee input's prevout is the miner fee and nothing else.
        let fee_sats = fee_prevout.value.to_sat();
        if fee_prevout.script_pubkey.as_bytes().is_empty() {
            return Err(CooperativeSettleError::EmptyFeeInputScript);
        }
        if !bounds.contains(fee_sats) {
            return Err(CooperativeSettleError::MinerFeeOutOfBounds {
                fee_sats,
                min_sats: bounds.min_sats,
                max_sats: bounds.max_sats,
            });
        }

        let transaction =
            candidate_transaction(&claim_outpoints, packages, destinations, fee_input);
        Ok(Self {
            statement_digest,
            packages: packages.to_vec(),
            destinations: destinations.to_vec(),
            fee_input,
            fee_prevout: fee_prevout.clone(),
            transaction,
        })
    }

    /// The manifest statement digest the claims commit.
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    /// The fee input whose value is the miner fee.
    pub fn fee_input(&self) -> OutPoint {
        self.fee_input
    }

    /// The miner fee the settlement leaves.
    pub fn miner_fee_sats(&self) -> u64 {
        self.fee_prevout.value.to_sat()
    }

    /// The ordered claim inputs, in transaction order.
    pub fn claim_outpoints(&self) -> Vec<OutPoint> {
        self.packages
            .iter()
            .map(|package| {
                let anchor = package
                    .claim_outpoint
                    .expect("a validated settlement package has an outpoint");
                OutPoint {
                    txid: bitcoin::Txid::from_byte_array(anchor.txid),
                    vout: anchor.vout,
                }
            })
            .collect()
    }

    /// The claim prevouts, in input order. The fee prevout is not included.
    pub fn claim_prevouts(&self) -> Result<Vec<TxOut>, CooperativeSettleError> {
        self.packages
            .iter()
            .enumerate()
            .map(|(index, package)| {
                let script_pubkey = package
                    .claim_scriptpubkey()
                    .ok_or(CooperativeSettleError::ClaimScriptpubkeyUnavailable { index })?;
                Ok(TxOut {
                    value: Amount::from_sat(package.entitlement_sats),
                    script_pubkey: ScriptBuf::from_bytes(script_pubkey),
                })
            })
            .collect()
    }

    /// The unsigned settlement transaction.
    pub fn transaction(&self) -> Transaction {
        self.transaction.clone()
    }

    /// Returns the BIP-341 script-path sighash for one claim input.
    ///
    /// `prevouts` must be the complete prevout list in input order: every claim prevout followed by
    /// the fee input's prevout. Every beneficiary signs with `SIGHASH_ALL`, so the digest covers the
    /// whole settlement and no signer can be shown a different one.
    pub fn claim_signing_hash(
        &self,
        index: usize,
        prevouts: &[TxOut],
    ) -> Result<[u8; 32], CooperativeSettleError> {
        if index >= self.packages.len() {
            return Err(CooperativeSettleError::UnknownClaimInput { index });
        }
        if prevouts.len() != self.packages.len() + 1 {
            return Err(CooperativeSettleError::PrevoutCountMismatch {
                expected: self.packages.len() + 1,
                found: prevouts.len(),
            });
        }
        let expected = self.claim_prevouts()?;
        for (position, claim_prevout) in expected.iter().enumerate() {
            if prevouts[position].script_pubkey != claim_prevout.script_pubkey
                || prevouts[position].value != claim_prevout.value
            {
                return Err(CooperativeSettleError::ClaimPrevoutMismatch { index: position });
            }
        }
        if prevouts[self.packages.len()] != self.fee_prevout {
            return Err(CooperativeSettleError::FeePrevoutMismatch);
        }

        let script = &self.packages[index].claim_script;
        let leaf_hash = TapLeafHash::from_byte_array(hash_tap_leaf(script, 0xc0));
        let sighash = SighashCache::new(&self.transaction)
            .taproot_signature_hash(
                index,
                &Prevouts::All(prevouts),
                None,
                Some((leaf_hash, 0xffff_ffff)),
                TapSighashType::Default,
            )
            .map_err(|_| CooperativeSettleError::SighashFailed)?;
        Ok(sighash.to_byte_array())
    }

    /// Assembles one claim input's recovery witness: `[signature, script, control block]`.
    pub fn claim_witness(
        &self,
        index: usize,
        signature: [u8; 64],
    ) -> Result<Witness, CooperativeSettleError> {
        let package = self
            .packages
            .get(index)
            .ok_or(CooperativeSettleError::UnknownClaimInput { index })?;
        Ok(Witness::from_slice(&[
            signature.to_vec(),
            package.claim_script.clone(),
            package.control_block.clone(),
        ]))
    }
}

/// Builds the transaction shape the builder and the verifier agree on.
fn candidate_transaction(
    claim_outpoints: &[OutPoint],
    packages: &[ClaimRecoveryPackage],
    destinations: &[ScriptBuf],
    fee_input: OutPoint,
) -> Transaction {
    let mut input = claim_outpoints
        .iter()
        .map(|outpoint| TxIn {
            previous_output: *outpoint,
            script_sig: ScriptBuf::new(),
            sequence: SETTLE_INPUT_SEQUENCE,
            witness: Witness::new(),
        })
        .collect::<Vec<_>>();
    input.push(TxIn {
        previous_output: fee_input,
        script_sig: ScriptBuf::new(),
        sequence: SETTLE_INPUT_SEQUENCE,
        witness: Witness::new(),
    });

    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output: destinations
            .iter()
            .zip(packages)
            .map(|(destination, package)| TxOut {
                value: Amount::from_sat(package.entitlement_sats),
                script_pubkey: destination.clone(),
            })
            .collect(),
    }
}

/// Rejection reasons for a cooperative settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CooperativeSettleError {
    /// The manifest itself is malformed.
    ManifestInvalid(ManifestError),
    /// The manifest has no beneficiary allocation to settle.
    NoBeneficiaryClaims,
    /// The package set does not have one package per beneficiary allocation.
    ClaimCountMismatch {
        /// The number of beneficiary allocations.
        expected: usize,
        /// The number of packages supplied.
        found: usize,
    },
    /// The destination list does not match the package list.
    DestinationCountMismatch {
        /// The number of packages.
        expected: usize,
        /// The number of destinations supplied.
        found: usize,
    },
    /// A package is not internally consistent.
    PackageInvalid(PackageError),
    /// A package has no claim outpoint or is marked discharged.
    ClaimNotRecoverable {
        /// The beneficiary-order index.
        index: usize,
    },
    /// A package describes another statement.
    StatementMismatch {
        /// The beneficiary-order index.
        index: usize,
    },
    /// A package names another beneficiary.
    BeneficiaryMismatch {
        /// The beneficiary-order index.
        index: usize,
    },
    /// A package's entitlement differs from the manifest payout.
    EntitlementMismatch {
        /// The beneficiary-order index.
        index: usize,
        /// The manifest amount.
        manifest_sats: u64,
        /// The package amount.
        package_sats: u64,
    },
    /// A package has no claim outpoint.
    MissingClaimOutpoint {
        /// The beneficiary-order index.
        index: usize,
    },
    /// The fee input is one of the claims.
    FeeInputConflictsWithClaim {
        /// The beneficiary-order index.
        index: usize,
    },
    /// Two packages point at the same claim outpoint.
    RepeatedClaimOutpoint {
        /// The beneficiary-order index that repeats an earlier claim.
        index: usize,
    },
    /// A destination script is empty.
    EmptyDestination {
        /// The beneficiary-order index.
        index: usize,
    },
    /// The fee input's script is empty, so it cannot be spent.
    EmptyFeeInputScript,
    /// The claim scriptpubkey could not be derived.
    ClaimScriptpubkeyUnavailable {
        /// The beneficiary-order index.
        index: usize,
    },
    /// The transaction shape is not the one the graph commits to.
    TransactionShapeMismatch,
    /// A claim input spends another outpoint or sequence.
    TransactionInputMismatch {
        /// The input index that differs.
        index: usize,
    },
    /// A claim output pays another amount or destination.
    TransactionOutputMismatch {
        /// The output index that differs.
        index: usize,
    },
    /// The fee input is not the last input or changes its sequence.
    FeeInputMismatch,
    /// The miner fee lies outside the range the caller accepts.
    MinerFeeOutOfBounds {
        /// The fee.
        fee_sats: u64,
        /// The smallest accepted fee.
        min_sats: u64,
        /// The largest accepted fee.
        max_sats: u64,
    },
    /// The caller asked for a claim input that does not exist.
    UnknownClaimInput {
        /// The requested index.
        index: usize,
    },
    /// The prevout list is not one claim prevout per claim plus the fee prevout.
    PrevoutCountMismatch {
        /// The expected count.
        expected: usize,
        /// The supplied count.
        found: usize,
    },
    /// A supplied claim prevout does not match the package's claim.
    ClaimPrevoutMismatch {
        /// The prevout index that differs.
        index: usize,
    },
    /// The supplied fee prevout is not the settlement's fee prevout.
    FeePrevoutMismatch,
    /// The sighash could not be computed.
    SighashFailed,
}
