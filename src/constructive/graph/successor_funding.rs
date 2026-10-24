//! The `SuccessorFunding` edge of the splitter graph.
//!
//! `SuccessorFunding` spends a confirmed `Deposit` and creates the ownership the participants rely
//! on once the Engine is gone (specification.md section 9.2). For the bounded `FixedSplitVaultV1`
//! profile the tree is flat:
//!
//! ```text
//! input  0: the deposit outpoint (key path, participant + Engine)
//! output 0..n: one output per manifest payout, in manifest order
//! output n: OP_RETURN carrying the statement digest
//! ```
//!
//! # The rule this module enforces
//!
//! [`SuccessorFunding::verify`] takes the counterparty's *transaction* — not a descriptor built by
//! the caller — and re-derives every obligation from the manifest. A signer therefore checks the
//! bytes it is about to sign, and cannot be tricked into authorising a successor that drops a
//! claim, redirects an amount, reorders recipients, commits a different statement, adds an
//! unaccounted output, or leaves a fee outside the accepted range.
//!
//! [`SuccessorFunding::new`] builds a candidate transaction and then runs the same verifier over it,
//! so there is exactly one implementation of the rule and the builder cannot drift from it.
//!
//! # What this module does not enforce
//!
//! - **The execution-fee output's script.** The manifest carries the fee recipient's key, but no
//!   canonical key-to-script derivation is pinned in this repository. The verifier checks that the
//!   fee output exists with the right amount and records its script; the signer authorises that
//!   script by signing. Binding it to the key is part of `BIND-01`, not of this module.
//! - **The fee policy.** The miner fee is whatever the deposit leaves after the obligations, and
//!   [`FeeBounds`] only checks it lies in the range the caller accepts. Deriving that range from a
//!   fee rate and the transaction's vsize is caller policy.
//! - **The dispute branch.** `ExitRequest`, `Assert`, `Take` and `Disprove` are separate roles, so
//!   `GRAPH-01` stays open.
//! - **Signing.** No key material is touched. The descriptor says what may be signed, not how.
//!
//! # Why the remainder must be the miner fee
//!
//! A change output would return value to the funder, which is both an un-declared obligation and a
//! second place a reviewer has to look for leakage. Requiring `deposit = obligations + miner_fee`
//! makes the successor fully accounted for: every satoshi is either an obligation the manifest
//! names or the fee both signers see in the sighash.

use crate::constructive::contracts::fixed_split_vault_v1::claim::{
    claim_scriptpubkey, statement_op_return_script,
};
use crate::model::fixed_split_vault_v1::manifest::{ManifestError, PayoutKind, TransitionManifest};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// The input sequence the descriptor commits to.
///
/// Opt-in RBF so a stuck funding spend can be fee-bumped, and no relative locktime because this
/// edge carries no maturity condition. Both values are covered by every signature over the
/// transaction, so changing them changes what was authorised.
pub const SUCCESSOR_INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// The deposit the successor spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositAnchor {
    /// The deposit outpoint.
    pub outpoint: OutPoint,
    /// The value of that output in satoshis.
    pub value_sats: u64,
}

impl DepositAnchor {
    /// Constructs an anchor.
    pub fn new(outpoint: OutPoint, value_sats: u64) -> Self {
        Self {
            outpoint,
            value_sats,
        }
    }
}

/// The miner fee range a signer is willing to authorise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeBounds {
    /// The smallest acceptable fee in satoshis.
    pub min_sats: u64,
    /// The largest acceptable fee in satoshis.
    pub max_sats: u64,
}

impl FeeBounds {
    /// Constructs a fee range.
    pub fn new(min_sats: u64, max_sats: u64) -> Self {
        Self { min_sats, max_sats }
    }

    /// Returns whether an amount lies inside the range.
    pub fn contains(self, fee_sats: u64) -> bool {
        fee_sats >= self.min_sats && fee_sats <= self.max_sats
    }
}

/// One output of the successor funding, in transaction order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingOutput {
    /// A beneficiary allocation, spendable only through the claim script.
    Claim {
        /// The beneficiary the claim is bound to.
        beneficiary_key: [u8; 32],
        /// The allocation in satoshis.
        amount_sats: u64,
        /// The taproot output key script committing to the statement and the key.
        script_pubkey: ScriptBuf,
    },
    /// The disclosed execution fee, paid to the fee account.
    ExecutionFee {
        /// The fee account key named by the manifest.
        recipient_key: [u8; 32],
        /// The fee in satoshis.
        amount_sats: u64,
        /// The output script, authorised by signature rather than derived.
        script_pubkey: ScriptBuf,
    },
    /// The `CBV1` `OP_RETURN` that publishes the statement digest.
    StatementCommitment {
        /// The committed statement digest.
        statement_digest: [u8; 32],
        /// The `OP_RETURN` script.
        script_pubkey: ScriptBuf,
    },
}

impl FundingOutput {
    /// Returns the value this output carries in satoshis.
    pub fn amount_sats(&self) -> u64 {
        match self {
            Self::Claim { amount_sats, .. } | Self::ExecutionFee { amount_sats, .. } => {
                *amount_sats
            }
            Self::StatementCommitment { .. } => 0,
        }
    }

    /// Returns the output script.
    pub fn script_pubkey(&self) -> &ScriptBuf {
        match self {
            Self::Claim { script_pubkey, .. }
            | Self::ExecutionFee { script_pubkey, .. }
            | Self::StatementCommitment { script_pubkey, .. } => script_pubkey,
        }
    }
}

/// A verified `SuccessorFunding` transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessorFunding {
    deposit: DepositAnchor,
    statement_digest: [u8; 32],
    miner_fee_sats: u64,
    outputs: Vec<FundingOutput>,
}

impl SuccessorFunding {
    /// Builds the successor funding for `manifest` and verifies it before returning.
    ///
    /// `execution_fee_script` must be present exactly when the manifest declares an execution-fee
    /// payout: the script is not derivable from the manifest's key, so it is supplied here and then
    /// authorised by signature.
    pub fn new(
        manifest: &TransitionManifest,
        deposit: DepositAnchor,
        miner_fee_sats: u64,
        execution_fee_script: Option<ScriptBuf>,
    ) -> Result<Self, SuccessorFundingError> {
        // 1 A malformed manifest cannot produce a well-formed funding transaction.
        manifest
            .validate()
            .map_err(SuccessorFundingError::ManifestInvalid)?;

        let statement_digest = manifest.statement_digest();
        let mut outputs = Vec::with_capacity(manifest.payouts.len() + 1);
        let mut execution_fee_script = execution_fee_script;
        let mut execution_fee_seen = false;

        // 2 One output per payout, in manifest order.
        for payout in &manifest.payouts {
            match payout.kind {
                PayoutKind::BeneficiaryAllocation => {
                    let script = claim_scriptpubkey(statement_digest, payout.recipient_key).ok_or(
                        SuccessorFundingError::ClaimScriptDerivationFailed {
                            beneficiary_key: payout.recipient_key,
                        },
                    )?;
                    outputs.push(FundingOutput::Claim {
                        beneficiary_key: payout.recipient_key,
                        amount_sats: payout.amount_sats,
                        script_pubkey: ScriptBuf::from_bytes(script),
                    });
                }
                PayoutKind::ExecutionFee => {
                    if execution_fee_seen {
                        return Err(SuccessorFundingError::MultipleExecutionFees);
                    }
                    execution_fee_seen = true;

                    let script = execution_fee_script
                        .take()
                        .ok_or(SuccessorFundingError::MissingExecutionFeeScript)?;
                    outputs.push(FundingOutput::ExecutionFee {
                        recipient_key: payout.recipient_key,
                        amount_sats: payout.amount_sats,
                        script_pubkey: script,
                    });
                }
                PayoutKind::NativeSuccessor => {
                    // A redemption is an internal transition; it is not funded by a Bitcoin
                    // successor. Paying it here would turn an internal entitlement into a second
                    // on-chain claim.
                    return Err(SuccessorFundingError::UnsupportedPayoutKind {
                        kind: PayoutKind::NativeSuccessor,
                    });
                }
            }
        }

        // 3 A supplied fee script that no payout consumes is a signer trap: it would look
        //   authorised while paying nobody the manifest names.
        if execution_fee_script.is_some() {
            return Err(SuccessorFundingError::UnusedExecutionFeeScript);
        }

        // 4 Publish the statement digest so the claims are linked to the manifest from Bitcoin
        //   alone, without reading any witness.
        outputs.push(FundingOutput::StatementCommitment {
            statement_digest,
            script_pubkey: ScriptBuf::from_bytes(statement_op_return_script(statement_digest)),
        });

        // 5 Build the candidate and run the verifier over it. One implementation of the rule.
        let candidate = candidate_transaction(deposit.outpoint, &outputs);
        Self::verify(
            &candidate,
            manifest,
            deposit.outpoint,
            deposit.value_sats,
            FeeBounds::new(miner_fee_sats, miner_fee_sats),
        )
    }

    /// Verifies a successor funding transaction against the manifest and returns the descriptor it
    /// authorises.
    ///
    /// This is the check to run on counterparty bytes before signing. The fee output's script is
    /// taken from the transaction and recorded, because it cannot be derived from the manifest key;
    /// the signature over the transaction is what authorises it.
    pub fn verify(
        transaction: &Transaction,
        manifest: &TransitionManifest,
        deposit_outpoint: OutPoint,
        deposit_value_sats: u64,
        bounds: FeeBounds,
    ) -> Result<Self, SuccessorFundingError> {
        // 1 A malformed manifest cannot authorise anything.
        manifest
            .validate()
            .map_err(SuccessorFundingError::ManifestInvalid)?;
        let statement_digest = manifest.statement_digest();

        // 2 Version, locktime and input shape are part of what a signature authorises.
        if transaction.version != Version::TWO
            || transaction.lock_time != LockTime::ZERO
            || transaction.input.len() != 1
        {
            return Err(SuccessorFundingError::TransactionShapeMismatch);
        }
        let input = &transaction.input[0];
        if input.previous_output != deposit_outpoint || input.sequence != SUCCESSOR_INPUT_SEQUENCE {
            return Err(SuccessorFundingError::TransactionInputMismatch);
        }

        // 3 The outputs must be exactly one per payout plus the commitment, in order.
        let expected_outputs = manifest.payouts.len() + 1;
        if transaction.output.len() != expected_outputs {
            return Err(SuccessorFundingError::UnexpectedOutputCount {
                expected: expected_outputs,
                found: transaction.output.len(),
            });
        }

        let mut outputs = Vec::with_capacity(expected_outputs);
        let mut execution_fee_seen = false;

        for (index, payout) in manifest.payouts.iter().enumerate() {
            let txout = &transaction.output[index];
            if txout.value.to_sat() != payout.amount_sats {
                return Err(SuccessorFundingError::PayoutOutputMismatch { index });
            }

            match payout.kind {
                PayoutKind::BeneficiaryAllocation => {
                    let expected = claim_scriptpubkey(statement_digest, payout.recipient_key)
                        .ok_or(SuccessorFundingError::ClaimScriptDerivationFailed {
                            beneficiary_key: payout.recipient_key,
                        })?;
                    if txout.script_pubkey != ScriptBuf::from_bytes(expected) {
                        return Err(SuccessorFundingError::PayoutOutputMismatch { index });
                    }
                    outputs.push(FundingOutput::Claim {
                        beneficiary_key: payout.recipient_key,
                        amount_sats: payout.amount_sats,
                        script_pubkey: txout.script_pubkey.clone(),
                    });
                }
                PayoutKind::ExecutionFee => {
                    if execution_fee_seen {
                        return Err(SuccessorFundingError::MultipleExecutionFees);
                    }
                    execution_fee_seen = true;

                    // The script is authorised by signature, not derived. Record what is there.
                    outputs.push(FundingOutput::ExecutionFee {
                        recipient_key: payout.recipient_key,
                        amount_sats: payout.amount_sats,
                        script_pubkey: txout.script_pubkey.clone(),
                    });
                }
                PayoutKind::NativeSuccessor => {
                    return Err(SuccessorFundingError::UnsupportedPayoutKind {
                        kind: PayoutKind::NativeSuccessor,
                    });
                }
            }
        }

        // 4 The final output must publish this manifest's statement digest, at zero value.
        let commitment = &transaction.output[expected_outputs - 1];
        let expected_commitment =
            ScriptBuf::from_bytes(statement_op_return_script(statement_digest));
        if commitment.value.to_sat() != 0 || commitment.script_pubkey != expected_commitment {
            return Err(SuccessorFundingError::StatementCommitmentMismatch);
        }
        outputs.push(FundingOutput::StatementCommitment {
            statement_digest,
            script_pubkey: expected_commitment,
        });

        // 5 The deposit must fund every output and leave exactly the claimed fee. A sum above the
        //   deposit is underfunded; the remainder is the fee and has to be acceptable.
        let spent_sats = transaction
            .output
            .iter()
            .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()))
            .ok_or(SuccessorFundingError::ValueOverflow)?;
        let miner_fee_sats = deposit_value_sats.checked_sub(spent_sats).ok_or(
            SuccessorFundingError::DepositUnderfunded {
                deposit_sats: deposit_value_sats,
                outputs_sats: spent_sats,
            },
        )?;
        if !bounds.contains(miner_fee_sats) {
            return Err(SuccessorFundingError::MinerFeeOutOfBounds {
                fee_sats: miner_fee_sats,
                min_sats: bounds.min_sats,
                max_sats: bounds.max_sats,
            });
        }

        Ok(Self {
            deposit: DepositAnchor::new(deposit_outpoint, deposit_value_sats),
            statement_digest,
            miner_fee_sats,
            outputs,
        })
    }

    /// The deposit being spent.
    pub fn deposit(&self) -> DepositAnchor {
        self.deposit
    }

    /// The statement digest committed by the claims and the `OP_RETURN`.
    pub fn statement_digest(&self) -> [u8; 32] {
        self.statement_digest
    }

    /// The miner fee the transaction leaves unspent.
    pub fn miner_fee_sats(&self) -> u64 {
        self.miner_fee_sats
    }

    /// The ordered outputs.
    pub fn outputs(&self) -> &[FundingOutput] {
        &self.outputs
    }

    /// Returns the execution-fee script, if the manifest declared an execution fee.
    pub fn execution_fee_script(&self) -> Option<ScriptBuf> {
        self.outputs.iter().find_map(|output| match output {
            FundingOutput::ExecutionFee { script_pubkey, .. } => Some(script_pubkey.clone()),
            _ => None,
        })
    }

    /// Builds the unsigned transaction this descriptor authorises.
    ///
    /// The witness is left empty on purpose: the only spend is the deposit's key path, produced by
    /// the participant and the Engine after both have verified the transaction.
    pub fn transaction(&self) -> Transaction {
        candidate_transaction(self.deposit.outpoint, &self.outputs)
    }
}

/// Builds the transaction shape both the builder and the verifier agree on.
fn candidate_transaction(deposit_outpoint: OutPoint, outputs: &[FundingOutput]) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: deposit_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: SUCCESSOR_INPUT_SEQUENCE,
            witness: Witness::new(),
        }],
        output: outputs
            .iter()
            .map(|output| TxOut {
                value: Amount::from_sat(output.amount_sats()),
                script_pubkey: output.script_pubkey().clone(),
            })
            .collect(),
    }
}

/// Rejection reasons for successor funding.
///
/// Every variant is a pure function of the manifest, the anchor and the transaction, so two
/// implementations agree on the error as well as on acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessorFundingError {
    /// The manifest itself is malformed.
    ManifestInvalid(ManifestError),
    /// Two execution-fee payouts were declared; the graph allows at most one.
    MultipleExecutionFees,
    /// An execution-fee payout exists but no script was supplied for it.
    MissingExecutionFeeScript,
    /// A fee script was supplied but no execution-fee payout consumes it.
    UnusedExecutionFeeScript,
    /// The payout kind cannot be funded by a Bitcoin successor.
    UnsupportedPayoutKind {
        /// The rejected kind.
        kind: PayoutKind,
    },
    /// The claim output key could not be derived for a beneficiary.
    ClaimScriptDerivationFailed {
        /// The beneficiary key that failed.
        beneficiary_key: [u8; 32],
    },
    /// The transaction's version, locktime or input count differs from the graph.
    TransactionShapeMismatch,
    /// The transaction spends something other than the anchored deposit, or changes its sequence.
    TransactionInputMismatch,
    /// The transaction does not have one output per payout plus the commitment.
    UnexpectedOutputCount {
        /// The expected count.
        expected: usize,
        /// The found count.
        found: usize,
    },
    /// The output at a payout's index has the wrong value or script.
    PayoutOutputMismatch {
        /// The payout index that differs.
        index: usize,
    },
    /// The final output does not publish this manifest's statement digest.
    StatementCommitmentMismatch,
    /// The sum of outputs overflows; no real transaction can.
    ValueOverflow,
    /// The outputs are worth more than the deposit.
    DepositUnderfunded {
        /// The deposit value offered.
        deposit_sats: u64,
        /// The value the outputs require.
        outputs_sats: u64,
    },
    /// The miner fee lies outside the range the signer accepts.
    MinerFeeOutOfBounds {
        /// The fee the transaction leaves.
        fee_sats: u64,
        /// The smallest accepted fee.
        min_sats: u64,
        /// The largest accepted fee.
        max_sats: u64,
    },
}
