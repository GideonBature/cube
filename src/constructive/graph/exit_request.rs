//! The `ExitRequest` role: an on-chain notice that a participant is leaving the cooperative path.
//!
//! specification.md section 9.2 asks this role to "record the refused operation and bind a specific
//! existing claim/anchor; specify deadlines and data disclosure". This module implements exactly
//! that and nothing more:
//!
//! ```text
//! OP_RETURN 0x04 "CBX1" 0x20 <exit_commitment> 0x24 <claim txid 32 || vout u32 LE>
//! ```
//!
//! 76 bytes, which keeps the output a standard `OP_RETURN` (the 80-byte data limit). The on-chain
//! bytes carry the claim locator and one commitment; the terms themselves are the preimage:
//!
//! ```text
//! version u8 | claim txid [32] | vout u32 LE | statement digest [32]
//!            | deadline height u64 LE | operation id [32] | data descriptor digest [32]
//! ```
//!
//! # Why a commitment and not the terms
//!
//! The full preimage is 141 bytes and does not fit in a standard `OP_RETURN`. The commitment binds
//! every term, and the preimage is published off-chain (in the recovery package's data descriptor).
//! A challenger who receives the preimage can recompute [`exit_commitment`] and compare it with the
//! chain, so the notice is verifiable even though it is compact.
//!
//! # What this role does not do
//!
//! - **It does not force a dispute.** Recording intent is not the same as making the Engine's path
//!   contestable; `Assert`, `Take` and `Disprove` are still blocked on label binding (`BIND-01`).
//! - **It does not prove data availability.** `data_descriptor_digest` commits to where the proof,
//!   manifest and labels will be published. A commitment is not availability.
//! - **It does not enforce the deadline.** The height is recorded, not checked by script; a client
//!   decides what to do when it passes.
//! - **It does not authenticate the requester.** Anybody can pay for this output. Whether the
//!   requester is a participant is decided by the claim's own ownership, off-chain.

use crate::transmutative::hash::{Hash, HashTag};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash as _;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

/// The tagged-hash tag of an exit commitment.
///
/// Frozen: changing it changes every recorded exit request.
pub const EXIT_COMMITMENT_TAG: &str = "CubeV1/ExitRequest/v0";

/// The schema version byte of the exit terms.
pub const EXIT_SCHEMA_VERSION: u8 = 1;

/// The four magic bytes an exit request carries.
pub const EXIT_MAGIC: [u8; 4] = *b"CBX1";

/// The frozen script length, in bytes.
pub const EXIT_SCRIPT_LEN: usize = 76;

/// The frozen preimage length, in bytes.
pub const EXIT_PREIMAGE_LEN: usize = 141;

/// The input sequence the notice commits to.
pub const EXIT_INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// The terms an exit request commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitTerms {
    /// The claim the requester is leaving through.
    pub claim_outpoint: OutPoint,
    /// The statement digest the claim commits to.
    pub statement_digest: [u8; 32],
    /// The height after which the exit is considered stale.
    pub deadline_height: u64,
    /// The operation whose refusal motivated the exit.
    pub operation_id: [u8; 32],
    /// The commitment to where the proof, manifest and labels are published.
    pub data_descriptor_digest: [u8; 32],
}

impl ExitTerms {
    /// Constructs terms.
    pub fn new(
        claim_outpoint: OutPoint,
        statement_digest: [u8; 32],
        deadline_height: u64,
        operation_id: [u8; 32],
        data_descriptor_digest: [u8; 32],
    ) -> Self {
        Self {
            claim_outpoint,
            statement_digest,
            deadline_height,
            operation_id,
            data_descriptor_digest,
        }
    }

    /// Returns the frozen preimage of the commitment.
    pub fn preimage(&self) -> [u8; EXIT_PREIMAGE_LEN] {
        let mut preimage = [0u8; EXIT_PREIMAGE_LEN];

        let mut cursor = 0;
        preimage[cursor] = EXIT_SCHEMA_VERSION;
        cursor += 1;

        preimage[cursor..cursor + 32].copy_from_slice(&self.claim_outpoint.txid.to_byte_array());
        cursor += 32;

        preimage[cursor..cursor + 4].copy_from_slice(&self.claim_outpoint.vout.to_le_bytes());
        cursor += 4;

        preimage[cursor..cursor + 32].copy_from_slice(&self.statement_digest);
        cursor += 32;

        preimage[cursor..cursor + 8].copy_from_slice(&self.deadline_height.to_le_bytes());
        cursor += 8;

        preimage[cursor..cursor + 32].copy_from_slice(&self.operation_id);
        cursor += 32;

        preimage[cursor..cursor + 32].copy_from_slice(&self.data_descriptor_digest);

        preimage
    }
}

/// Returns the commitment of `terms`.
pub fn exit_commitment(terms: &ExitTerms) -> [u8; 32] {
    terms
        .preimage()
        .hash(Some(HashTag::CustomString(EXIT_COMMITMENT_TAG.to_string())))
}

/// A parsed or constructed exit request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitRequest {
    claim_outpoint: OutPoint,
    commitment: [u8; 32],
}

impl ExitRequest {
    /// Builds the request for `terms`.
    pub fn new(terms: &ExitTerms) -> Self {
        Self {
            claim_outpoint: terms.claim_outpoint,
            commitment: exit_commitment(terms),
        }
    }

    /// The claim the notice refers to.
    pub fn claim_outpoint(&self) -> OutPoint {
        self.claim_outpoint
    }

    /// The committed terms.
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Returns the frozen `OP_RETURN` script.
    pub fn script(&self) -> ScriptBuf {
        let mut script = Vec::with_capacity(EXIT_SCRIPT_LEN);

        // 1 `OP_RETURN`, then the magic as a four-byte push.
        script.push(0x6a);
        script.push(EXIT_MAGIC.len() as u8);
        script.extend(EXIT_MAGIC);

        // 2 The exit commitment as a 32-byte push.
        script.push(32);
        script.extend(self.commitment);

        // 3 The claim locator as a 36-byte push.
        script.push(36);
        script.extend(self.claim_outpoint.txid.to_byte_array());
        script.extend(self.claim_outpoint.vout.to_le_bytes());

        debug_assert_eq!(script.len(), EXIT_SCRIPT_LEN);
        ScriptBuf::from_bytes(script)
    }

    /// Parses a script that must be exactly an exit request.
    ///
    /// Returns `None` for anything that is not the frozen layout: a different length, a different
    /// opcode, a different magic, or a different push structure. A witness or a script that merely
    /// starts with `OP_RETURN` is not an exit request.
    pub fn parse(script: &[u8]) -> Option<Self> {
        if script.len() != EXIT_SCRIPT_LEN {
            return None;
        }
        if script[0] != 0x6a {
            return None;
        }
        if script[1] != EXIT_MAGIC.len() as u8 || script[2..6] != EXIT_MAGIC {
            return None;
        }
        if script[6] != 32 {
            return None;
        }

        let mut commitment = [0u8; 32];
        commitment.copy_from_slice(&script[7..39]);

        if script[39] != 36 {
            return None;
        }

        let mut txid = [0u8; 32];
        txid.copy_from_slice(&script[40..72]);
        let mut vout = [0u8; 4];
        vout.copy_from_slice(&script[72..76]);

        Some(Self {
            claim_outpoint: OutPoint {
                txid: Txid::from_byte_array(txid),
                vout: u32::from_le_bytes(vout),
            },
            commitment,
        })
    }

    /// Checks this request against the terms a challenger reconstructed.
    pub fn verify(&self, terms: &ExitTerms) -> Result<(), ExitRequestError> {
        if self.claim_outpoint != terms.claim_outpoint {
            return Err(ExitRequestError::ClaimMismatch {
                recorded: self.claim_outpoint,
                expected: terms.claim_outpoint,
            });
        }

        let expected = exit_commitment(terms);
        if self.commitment != expected {
            return Err(ExitRequestError::CommitmentMismatch {
                recorded: self.commitment,
                expected,
            });
        }

        Ok(())
    }

    /// Builds the notice transaction: one funding input, the notice, and change.
    ///
    /// The input is the requester's, so the caller names it and its value. The only rule here is
    /// that the fee cannot consume the input.
    pub fn transaction(
        &self,
        funding_outpoint: OutPoint,
        funding_value_sats: u64,
        change_script: ScriptBuf,
        miner_fee_sats: u64,
    ) -> Result<Transaction, ExitRequestError> {
        if miner_fee_sats >= funding_value_sats {
            return Err(ExitRequestError::FeeExceedsValue {
                value_sats: funding_value_sats,
                fee_sats: miner_fee_sats,
            });
        }

        Ok(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: EXIT_INPUT_SEQUENCE,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: self.script(),
                },
                TxOut {
                    value: Amount::from_sat(funding_value_sats - miner_fee_sats),
                    script_pubkey: change_script,
                },
            ],
        })
    }
}

/// Rejection reasons for an exit request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitRequestError {
    /// The request names a different claim than the terms.
    ClaimMismatch {
        /// The claim the request records.
        recorded: OutPoint,
        /// The claim the terms describe.
        expected: OutPoint,
    },
    /// The commitment does not match the terms.
    CommitmentMismatch {
        /// The commitment on chain.
        recorded: [u8; 32],
        /// The commitment the terms produce.
        expected: [u8; 32],
    },
    /// The requested fee consumes the whole input.
    FeeExceedsValue {
        /// The input value.
        value_sats: u64,
        /// The requested fee.
        fee_sats: u64,
    },
}
