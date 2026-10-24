//! The `Assert`, `Take` and `Disprove` edges of the splitter's dispute graph.
//!
//! A claim output commits a statement digest but not a proof. This module adds the assertion the
//! claim's owner signs, the timelocked valid-claim settlement, and the secret-based dispute. The
//! binding construction is specified in `docs/bind_01.md`; this module is the executable half.
//!
//! ```text
//! claim v2 leaf   <D> OP_DROP <B> OP_DROP <beneficiary> OP_CHECKSIG        (Assert input)
//! assertion       taproot { Take, Disprove }, no key path
//! Take            <B> OP_DROP <csv> OP_CSV OP_DROP <operator> OP_CHECKSIG
//! Disprove        <B> OP_DROP OP_SHA256 <commitment> OP_EQUALVERIFY <beneficiary> OP_CHECKSIG
//! ```
//!
//! `B` is a tagged digest over [`AssertionTerms`]: the statement, the claim id, the setup instance,
//! the verifier key identity, the table digest, the disclosure commitment, the authenticated input
//! digest and the challenge window. Because `B` is inside both leaves, the assertion output key
//! commits all of it. The `Assert` input's BIP-341 sighash covers that output *and* the claim
//! outpoint and value, so the beneficiary's signature over the input is a signature over the exact
//! proof input bytes and the exact claim being spent.
//!
//! # What this module enforces
//!
//! [`Assertion::verify`] and the two spend verifiers take the transaction, not a descriptor built by
//! the caller, and re-derive the shape, scripts, values and timelocks. [`DisproveSpend::new`]
//! refuses a secret that does not open the committed hashlock.
//!
//! # What this module does not enforce
//!
//! - **The table evaluation.** No pairing check happens here. The challenger evaluates the
//!   published `AuthenticatedInput` from `cube-argo` with the table identified by `table_digest`;
//!   an error is a liveness failure, not acceptance (see `docs/bind_01.md` section 2).
//! - **The funding witness.** The `Assert` input's script and signature are supplied by the caller
//!   and checked by Bitcoin, not by this module.
//! - **Data availability.** The authenticated input and the table are off-chain objects. Their
//!   digests are commitments, not publication.
//! - **Which output is contested.** A claim, a fee output or an operator bond all work as the
//!   `Assert` input; the graph decision stays in `GRAPH-01`.

use crate::constructive::contracts::fixed_split_vault_v1::claim::claim_script;
use crate::constructive::graph::successor_funding::FeeBounds;
use crate::constructive::taproot::{TapLeaf, TapRoot};
use crate::transmutative::hash::{Hash, HashTag};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash as BitcoinHash;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

/// The frozen schema version of [`AssertionTerms`].
pub const ASSERTION_SCHEMA_VERSION: u8 = 1;

/// The tagged-hash tag of the assertion binding digest.
pub const ASSERTION_DIGEST_TAG: &str = "CubeV1/Assertion/v0";

/// The canonical length of a disclosure secret, in bytes.
pub const DISCLOSURE_SECRET_LEN: usize = 32;

/// The input sequence the `Assert` transaction commits to.
pub const ASSERT_INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

/// The input sequence a `Disprove` spend commits to.
pub const DISPROVE_INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

const OP_PUSH_32: u8 = 0x20;
const OP_DROP: u8 = 0x75;
const OP_CHECKSIG: u8 = 0xac;
const OP_SHA256: u8 = 0xa8;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;

/// A claim output that can be asserted as well as recovered.
///
/// The recovery leaf is the existing v1 claim script, so the beneficiary keeps its unconditional
/// exit. The assertion leaf adds the binding digest and requires the same beneficiary key.
pub struct AssertionClaim {
    statement_digest: [u8; 32],
    binding_digest: [u8; 32],
    beneficiary_key: [u8; 32],
    taproot: TapRoot,
}

impl Clone for AssertionClaim {
    fn clone(&self) -> Self {
        Self {
            statement_digest: self.statement_digest,
            binding_digest: self.binding_digest,
            beneficiary_key: self.beneficiary_key,
            taproot: self.taproot.clone(),
        }
    }
}

impl AssertionClaim {
    /// Builds the two-leaf claim taproot.
    pub fn new(
        statement_digest: [u8; 32],
        binding_digest: [u8; 32],
        beneficiary_key: [u8; 32],
    ) -> Result<Self, AssertionError> {
        if beneficiary_key == [0u8; 32] {
            return Err(AssertionError::ZeroBeneficiaryKey);
        }
        let taproot = TapRoot::script_path_only_multi(vec![
            TapLeaf::new(claim_script(statement_digest, beneficiary_key)),
            TapLeaf::new(assertion_claim_script(
                statement_digest,
                binding_digest,
                beneficiary_key,
            )),
        ]);
        Ok(Self {
            statement_digest,
            binding_digest,
            beneficiary_key,
            taproot,
        })
    }

    /// Returns the claim scriptpubkey.
    pub fn scriptpubkey(&self) -> Result<ScriptBuf, AssertionError> {
        self.taproot
            .spk()
            .map(ScriptBuf::from_bytes)
            .ok_or(AssertionError::TaprootDegenerate)
    }

    /// Returns the recovery leaf script.
    pub fn recovery_script(&self) -> Vec<u8> {
        claim_script(self.statement_digest, self.beneficiary_key)
    }

    /// Returns the assertion leaf script.
    pub fn assertion_script(&self) -> Vec<u8> {
        assertion_claim_script(
            self.statement_digest,
            self.binding_digest,
            self.beneficiary_key,
        )
    }

    /// Returns the control block for the recovery leaf (index 0).
    pub fn recovery_control_block(&self) -> Result<Vec<u8>, AssertionError> {
        self.taproot
            .control_block(0)
            .map(|block| block.to_vec())
            .ok_or(AssertionError::TaprootDegenerate)
    }

    /// Returns the control block for the assertion leaf (index 1).
    pub fn assertion_control_block(&self) -> Result<Vec<u8>, AssertionError> {
        self.taproot
            .control_block(1)
            .map(|block| block.to_vec())
            .ok_or(AssertionError::TaprootDegenerate)
    }

    /// Returns the BIP-341 script-path sighash the beneficiary signs for the `Assert` input.
    ///
    /// The signature covers every output of `transaction`, including the assertion output whose
    /// key commits the binding digest. `claim_prevout` must be the claim this taproot defines.
    pub fn assert_signing_hash(
        &self,
        transaction: &Transaction,
        claim_prevout: &TxOut,
    ) -> Result<[u8; 32], AssertionError> {
        if claim_prevout.script_pubkey != self.scriptpubkey()? {
            return Err(AssertionError::ClaimScriptMismatch);
        }

        let script = self.assertion_script();
        let leaf_hash = TapLeafHash::from_byte_array(crate::constructive::taproot::hash_tap_leaf(
            &script, 0xc0,
        ));
        let sighash = SighashCache::new(transaction)
            .taproot_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(claim_prevout)),
                None,
                Some((leaf_hash, 0xffff_ffff)),
                TapSighashType::Default,
            )
            .map_err(|_| AssertionError::SighashFailed)?;
        Ok(sighash.to_byte_array())
    }

    /// Assembles the assertion-leaf witness: `[signature, script, control block]`.
    pub fn assert_witness(&self, signature: [u8; 64]) -> Result<Witness, AssertionError> {
        Ok(Witness::from_slice(&[
            signature.to_vec(),
            self.assertion_script(),
            self.assertion_control_block()?,
        ]))
    }
}

/// Returns the v2 claim assertion leaf:
///
/// ```text
/// 0x20 <statement:32> 0x75 0x20 <binding:32> 0x75 0x20 <beneficiary:32> 0xac
/// ```
pub fn assertion_claim_script(
    statement_digest: [u8; 32],
    binding_digest: [u8; 32],
    beneficiary_key: [u8; 32],
) -> Vec<u8> {
    let mut script = Vec::with_capacity(102);
    script.push(OP_PUSH_32);
    script.extend(statement_digest);
    script.push(OP_DROP);
    script.push(OP_PUSH_32);
    script.extend(binding_digest);
    script.push(OP_DROP);
    script.push(OP_PUSH_32);
    script.extend(beneficiary_key);
    script.push(OP_CHECKSIG);
    script
}

/// Everything the assertion output commits to.
///
/// The encoding is frozen at [`ASSERTION_SCHEMA_VERSION`]; changing any field changes the binding
/// digest and therefore the output key, which invalidates every signature over an older value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionTerms {
    /// The statement digest the claim commits.
    pub statement_digest: [u8; 32],
    /// The stable claim identity from the recovery package.
    ///
    /// This is a salt, not the claim's outpoint: the claim script exists before the outpoint does,
    /// so committing the outpoint here would be circular. The `Assert` signature binds the actual
    /// outpoint and value through the BIP-341 sighash.
    pub claim_id: [u8; 32],
    /// The setup instance the table belongs to.
    pub setup_instance_id: [u8; 16],
    /// The verifier key identity, from the Argo adapter.
    pub verifier_key_identity: [u8; 32],
    /// The digest of the garbling table the challenger must obtain.
    pub table_digest: [u8; 32],
    /// The commitment the `Disprove` hashlock checks.
    pub secret_commitment: [u8; 32],
    /// The digest of the published authenticated input.
    pub input_digest: [u8; 32],
    /// The relative timelock, in blocks, before `Take` is valid.
    pub challenge_blocks: u32,
    /// The only key that can `Take`.
    pub operator_key: [u8; 32],
    /// The only key that can `Disprove`.
    pub beneficiary_key: [u8; 32],
}

impl AssertionTerms {
    /// Checks the terms before any script or digest is derived.
    pub fn validate(&self) -> Result<(), AssertionError> {
        // 1 The digest is a v1 statement digest: its top three bits are cleared by Amendment A1.
        if self.statement_digest[0] & 0xe0 != 0 {
            return Err(AssertionError::StatementDigestNotFieldSized);
        }

        // 2 No zero commitments or keys, which would make a commitment empty or a key meaningless.
        for (name, bytes) in [
            ("claim id", self.claim_id),
            ("verifier key identity", self.verifier_key_identity),
            ("table digest", self.table_digest),
            ("secret commitment", self.secret_commitment),
            ("input digest", self.input_digest),
            ("operator key", self.operator_key),
            ("beneficiary key", self.beneficiary_key),
        ] {
            if bytes == [0u8; 32] {
                return Err(AssertionError::ZeroField { field: name });
            }
        }
        if self.operator_key == self.beneficiary_key {
            return Err(AssertionError::RepeatedKey);
        }

        // 3 The challenge window is a relative block height that `OP_CSV` can encode.
        if self.challenge_blocks == 0 || self.challenge_blocks > u32::from(u16::MAX) {
            return Err(AssertionError::InvalidChallengeWindow {
                blocks: self.challenge_blocks,
            });
        }

        Ok(())
    }

    /// Returns the canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(277);
        buffer.push(ASSERTION_SCHEMA_VERSION);
        buffer.extend(self.statement_digest);
        buffer.extend(self.claim_id);
        buffer.extend(self.setup_instance_id);
        buffer.extend(self.verifier_key_identity);
        buffer.extend(self.table_digest);
        buffer.extend(self.secret_commitment);
        buffer.extend(self.input_digest);
        buffer.extend(self.challenge_blocks.to_le_bytes());
        buffer.extend(self.operator_key);
        buffer.extend(self.beneficiary_key);
        buffer
    }

    /// Returns the tagged binding digest embedded in both assertion leaves.
    pub fn binding_digest(&self) -> [u8; 32] {
        self.encode().hash(Some(HashTag::CustomString(
            ASSERTION_DIGEST_TAG.to_string(),
        )))
    }
}

/// The disclosure commitment for one secret.
///
/// The preimage is the canonical little-endian field encoding the Argo table returns. It is a plain
/// SHA-256, not a tagged hash, because `OP_SHA256` is what the `Disprove` leaf can compute; the
/// instance binding lives in the assertion digest `B`, which the same leaf embeds. A golden vector
/// in this module and in `crates/cube-argo` keeps the two implementations equal.
pub fn disclosure_secret_commitment(secret: &[u8; 32]) -> [u8; 32] {
    crate::transmutative::hash::sha256(secret)
}

/// Returns the `Take` leaf:
///
/// ```text
/// 0x20 <binding:32> 0x75 <csv> 0xb2 0x75 0x20 <operator:32> 0xac
/// ```
pub fn take_script(
    binding_digest: [u8; 32],
    challenge_blocks: u32,
    operator_key: [u8; 32],
) -> Vec<u8> {
    let mut script = Vec::with_capacity(74);
    script.push(OP_PUSH_32);
    script.extend(binding_digest);
    script.push(OP_DROP);
    push_script_number(&mut script, challenge_blocks);
    script.push(OP_CHECKSEQUENCEVERIFY);
    script.push(OP_DROP);
    script.push(OP_PUSH_32);
    script.extend(operator_key);
    script.push(OP_CHECKSIG);
    script
}

/// Returns the `Disprove` leaf:
///
/// ```text
/// 0x20 <binding:32> 0x75 0xa8 0x20 <commitment:32> 0x88 0x20 <beneficiary:32> 0xac
/// ```
pub fn disprove_script(
    binding_digest: [u8; 32],
    secret_commitment: [u8; 32],
    beneficiary_key: [u8; 32],
) -> Vec<u8> {
    let mut script = Vec::with_capacity(103);
    script.push(OP_PUSH_32);
    script.extend(binding_digest);
    script.push(OP_DROP);
    script.push(OP_SHA256);
    script.push(OP_PUSH_32);
    script.extend(secret_commitment);
    script.push(OP_EQUALVERIFY);
    script.push(OP_PUSH_32);
    script.extend(beneficiary_key);
    script.push(OP_CHECKSIG);
    script
}

/// Pushes a minimal script number, as `OP_CHECKSEQUENCEVERIFY` requires.
fn push_script_number(script: &mut Vec<u8>, value: u32) {
    match value {
        0 => script.push(0x00),
        1..=16 => script.push(0x50 + value as u8),
        _ => {
            let mut bytes = value.to_le_bytes().to_vec();
            while bytes.len() > 1 && bytes.last() == Some(&0) {
                bytes.pop();
            }
            // A set sign bit would make the number negative; Bitcoin's minimal encoding adds a
            // zero byte in that case.
            if let Some(last) = bytes.last() {
                if last & 0x80 != 0 {
                    bytes.push(0x00);
                }
            }
            script.push(bytes.len() as u8);
            script.extend(bytes);
        }
    }
}

/// The claim output an assertion spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContestedOutput {
    /// The outpoint holding the claim.
    pub outpoint: OutPoint,
    /// The claim value in satoshis.
    pub value_sats: u64,
}

/// The on-chain assertion output and the `Assert` transaction that creates it.
pub struct Assertion {
    terms: AssertionTerms,
    contested: ContestedOutput,
    assertion_value_sats: u64,
    taproot: TapRoot,
}

impl Clone for Assertion {
    fn clone(&self) -> Self {
        Self {
            terms: self.terms.clone(),
            contested: self.contested,
            assertion_value_sats: self.assertion_value_sats,
            taproot: self.taproot.clone(),
        }
    }
}

impl core::fmt::Debug for Assertion {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Assertion")
            .field("binding_digest", &self.binding_digest())
            .field("value_sats", &self.assertion_value_sats)
            .finish_non_exhaustive()
    }
}

impl Assertion {
    /// Builds the assertion output, paying `miner_fee_sats` from the contested value.
    pub fn new(
        terms: AssertionTerms,
        contested: ContestedOutput,
        miner_fee_sats: u64,
    ) -> Result<Self, AssertionError> {
        terms.validate()?;
        if contested.value_sats == 0 {
            return Err(AssertionError::ZeroContestedValue);
        }
        if miner_fee_sats >= contested.value_sats {
            return Err(AssertionError::FeeExceedsValue {
                value_sats: contested.value_sats,
                fee_sats: miner_fee_sats,
            });
        }

        let binding = terms.binding_digest();
        let taproot = TapRoot::script_path_only_multi(vec![
            TapLeaf::new(take_script(
                binding,
                terms.challenge_blocks,
                terms.operator_key,
            )),
            TapLeaf::new(disprove_script(
                binding,
                terms.secret_commitment,
                terms.beneficiary_key,
            )),
        ]);

        Ok(Self {
            assertion_value_sats: contested.value_sats - miner_fee_sats,
            terms,
            contested,
            taproot,
        })
    }

    /// The terms this assertion commits to.
    pub fn terms(&self) -> &AssertionTerms {
        &self.terms
    }

    /// The claim output this assertion spends.
    pub fn contested(&self) -> ContestedOutput {
        self.contested
    }

    /// The binding digest embedded in both leaves.
    pub fn binding_digest(&self) -> [u8; 32] {
        self.terms.binding_digest()
    }

    /// The value the assertion output holds.
    pub fn value_sats(&self) -> u64 {
        self.assertion_value_sats
    }

    /// The assertion scriptpubkey.
    pub fn scriptpubkey(&self) -> Result<ScriptBuf, AssertionError> {
        self.taproot
            .spk()
            .map(ScriptBuf::from_bytes)
            .ok_or(AssertionError::TaprootDegenerate)
    }

    /// The `Take` leaf script.
    pub fn take_script(&self) -> Vec<u8> {
        take_script(
            self.binding_digest(),
            self.terms.challenge_blocks,
            self.terms.operator_key,
        )
    }

    /// The `Disprove` leaf script.
    pub fn disprove_script(&self) -> Vec<u8> {
        disprove_script(
            self.binding_digest(),
            self.terms.secret_commitment,
            self.terms.beneficiary_key,
        )
    }

    /// The control block for the `Take` leaf (index 0).
    pub fn take_control_block(&self) -> Result<Vec<u8>, AssertionError> {
        self.taproot
            .control_block(0)
            .map(|block| block.to_vec())
            .ok_or(AssertionError::TaprootDegenerate)
    }

    /// The control block for the `Disprove` leaf (index 1).
    pub fn disprove_control_block(&self) -> Result<Vec<u8>, AssertionError> {
        self.taproot
            .control_block(1)
            .map(|block| block.to_vec())
            .ok_or(AssertionError::TaprootDegenerate)
    }

    /// Builds the `Assert` transaction: one contested input, one assertion output.
    ///
    /// `funding_witness` is the contested output's own witness (for the claim v2 leaf, the
    /// beneficiary's BIP-340 signature, the script and its control block). The signature covers
    /// the output script, so it covers the binding digest.
    pub fn transaction(&self, funding_witness: Witness) -> Result<Transaction, AssertionError> {
        Ok(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: self.contested.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: ASSERT_INPUT_SEQUENCE,
                witness: funding_witness,
            }],
            output: vec![TxOut {
                value: Amount::from_sat(self.assertion_value_sats),
                script_pubkey: self.scriptpubkey()?,
            }],
        })
    }

    /// Verifies an `Assert` transaction against the terms, the claim it spends and a fee range.
    pub fn verify(
        transaction: &Transaction,
        terms: &AssertionTerms,
        contested: ContestedOutput,
        bounds: FeeBounds,
    ) -> Result<Self, AssertionError> {
        terms.validate()?;

        if transaction.version != Version::TWO
            || transaction.lock_time != LockTime::ZERO
            || transaction.input.len() != 1
            || transaction.output.len() != 1
        {
            return Err(AssertionError::TransactionShapeMismatch);
        }
        let input = &transaction.input[0];
        if input.previous_output != contested.outpoint || input.sequence != ASSERT_INPUT_SEQUENCE {
            return Err(AssertionError::TransactionInputMismatch);
        }

        let spent_sats = transaction.output[0].value.to_sat();
        let miner_fee_sats = contested.value_sats.checked_sub(spent_sats).ok_or(
            AssertionError::OutputExceedsContested {
                contested_sats: contested.value_sats,
                output_sats: spent_sats,
            },
        )?;
        if !bounds.contains(miner_fee_sats) {
            return Err(AssertionError::MinerFeeOutOfBounds {
                fee_sats: miner_fee_sats,
                min_sats: bounds.min_sats,
                max_sats: bounds.max_sats,
            });
        }

        let assertion = Self::new(terms.clone(), contested, miner_fee_sats)?;
        let expected_script = assertion.scriptpubkey()?;
        if transaction.output[0].script_pubkey != expected_script {
            return Err(AssertionError::AssertionScriptMismatch);
        }

        Ok(assertion)
    }

    /// Returns the outpoint this assertion will occupy once `assert` is confirmed.
    pub fn outpoint(&self, assert_transaction: &Transaction) -> OutPoint {
        OutPoint {
            txid: assert_transaction.compute_txid(),
            vout: 0,
        }
    }
}

/// The output an assertion spend is anchored to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertionAnchor {
    /// The assertion output.
    pub outpoint: OutPoint,
    /// Its value.
    pub value_sats: u64,
}

impl AssertionAnchor {
    /// Constructs an anchor.
    pub fn new(outpoint: OutPoint, value_sats: u64) -> Self {
        Self {
            outpoint,
            value_sats,
        }
    }
}

/// A `Take` spend: the operator claims the assertion output after the challenge window.
#[derive(Debug, Clone)]
pub struct TakeSpend {
    assertion: Assertion,
    anchor: AssertionAnchor,
    destination_script: ScriptBuf,
    fee_sats: u64,
}

impl TakeSpend {
    /// Builds a `Take` spend to `destination_script`.
    pub fn new(
        assertion: &Assertion,
        anchor: AssertionAnchor,
        destination_script: ScriptBuf,
        fee_sats: u64,
    ) -> Result<Self, AssertionError> {
        if anchor.value_sats != assertion.value_sats() {
            return Err(AssertionError::AnchorValueMismatch {
                expected_sats: assertion.value_sats(),
                anchor_sats: anchor.value_sats,
            });
        }
        if fee_sats >= anchor.value_sats {
            return Err(AssertionError::FeeExceedsValue {
                value_sats: anchor.value_sats,
                fee_sats,
            });
        }

        Ok(Self {
            assertion: assertion.clone(),
            anchor,
            destination_script,
            fee_sats,
        })
    }

    /// The destination the operator is paid at.
    pub fn destination_script(&self) -> &ScriptBuf {
        &self.destination_script
    }

    /// The miner fee this spend leaves.
    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    /// The value the destination receives.
    pub fn output_value_sats(&self) -> u64 {
        self.anchor.value_sats - self.fee_sats
    }

    /// Builds the unsigned transaction. The input sequence is the challenge window.
    pub fn transaction(&self) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: self.anchor.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(self.assertion.terms.challenge_blocks),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(self.output_value_sats()),
                script_pubkey: self.destination_script.clone(),
            }],
        }
    }

    /// Returns the BIP-341 script-path sighash the operator must sign.
    pub fn signing_hash(&self, prevout: &TxOut) -> Result<[u8; 32], AssertionError> {
        let script = self.assertion.take_script();
        let leaf_hash = TapLeafHash::from_byte_array(crate::constructive::taproot::hash_tap_leaf(
            &script, 0xc0,
        ));
        let sighash = SighashCache::new(self.transaction())
            .taproot_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(prevout)),
                None,
                Some((leaf_hash, 0xffff_ffff)),
                TapSighashType::Default,
            )
            .map_err(|_| AssertionError::SighashFailed)?;
        Ok(sighash.to_byte_array())
    }

    /// Assembles the `Take` witness: `[signature, script, control block]`.
    pub fn witness(&self, signature: [u8; 64]) -> Result<Witness, AssertionError> {
        Ok(Witness::from_slice(&[
            signature.to_vec(),
            self.assertion.take_script(),
            self.assertion.take_control_block()?,
        ]))
    }

    /// Verifies an unsigned `Take` transaction against the assertion and a fee range.
    pub fn verify(
        transaction: &Transaction,
        assertion: &Assertion,
        anchor: AssertionAnchor,
        destination_script: &ScriptBuf,
        bounds: FeeBounds,
    ) -> Result<Self, AssertionError> {
        if transaction.version != Version::TWO
            || transaction.lock_time != LockTime::ZERO
            || transaction.input.len() != 1
            || transaction.output.len() != 1
        {
            return Err(AssertionError::TransactionShapeMismatch);
        }
        if !transaction.input[0].witness.is_empty() {
            return Err(AssertionError::TransactionShapeMismatch);
        }
        if transaction.input[0].previous_output != anchor.outpoint
            || transaction.input[0].sequence
                != Sequence::from_consensus(assertion.terms.challenge_blocks)
        {
            return Err(AssertionError::TransactionInputMismatch);
        }
        if transaction.output[0].script_pubkey != *destination_script {
            return Err(AssertionError::DestinationMismatch);
        }

        let fee_sats = anchor
            .value_sats
            .checked_sub(transaction.output[0].value.to_sat())
            .ok_or(AssertionError::OutputExceedsContested {
                contested_sats: anchor.value_sats,
                output_sats: transaction.output[0].value.to_sat(),
            })?;
        if !bounds.contains(fee_sats) {
            return Err(AssertionError::MinerFeeOutOfBounds {
                fee_sats,
                min_sats: bounds.min_sats,
                max_sats: bounds.max_sats,
            });
        }

        TakeSpend::new(assertion, anchor, destination_script.clone(), fee_sats)
    }
}

/// A `Disprove` spend: the beneficiary claims the assertion output with the disclosure secret.
#[derive(Debug, Clone)]
pub struct DisproveSpend {
    assertion: Assertion,
    anchor: AssertionAnchor,
    secret: [u8; DISCLOSURE_SECRET_LEN],
    destination_script: ScriptBuf,
    fee_sats: u64,
}

impl DisproveSpend {
    /// Builds a `Disprove` spend, refusing a secret that does not open the commitment.
    pub fn new(
        assertion: &Assertion,
        anchor: AssertionAnchor,
        secret: [u8; DISCLOSURE_SECRET_LEN],
        destination_script: ScriptBuf,
        fee_sats: u64,
    ) -> Result<Self, AssertionError> {
        if anchor.value_sats != assertion.value_sats() {
            return Err(AssertionError::AnchorValueMismatch {
                expected_sats: assertion.value_sats(),
                anchor_sats: anchor.value_sats,
            });
        }
        if fee_sats >= anchor.value_sats {
            return Err(AssertionError::FeeExceedsValue {
                value_sats: anchor.value_sats,
                fee_sats,
            });
        }
        let expected = disclosure_secret_commitment(&secret);
        if expected != assertion.terms.secret_commitment {
            return Err(AssertionError::WrongDisclosureSecret);
        }

        Ok(Self {
            assertion: assertion.clone(),
            anchor,
            secret,
            destination_script,
            fee_sats,
        })
    }

    /// The destination the beneficiary is paid at.
    pub fn destination_script(&self) -> &ScriptBuf {
        &self.destination_script
    }

    /// The miner fee this spend leaves.
    pub fn fee_sats(&self) -> u64 {
        self.fee_sats
    }

    /// The value the destination receives.
    pub fn output_value_sats(&self) -> u64 {
        self.anchor.value_sats - self.fee_sats
    }

    /// Builds the unsigned transaction. There is no timelock on this leaf.
    pub fn transaction(&self) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: self.anchor.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: DISPROVE_INPUT_SEQUENCE,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(self.output_value_sats()),
                script_pubkey: self.destination_script.clone(),
            }],
        }
    }

    /// Returns the BIP-341 script-path sighash the beneficiary must sign.
    pub fn signing_hash(&self, prevout: &TxOut) -> Result<[u8; 32], AssertionError> {
        let script = self.assertion.disprove_script();
        let leaf_hash = TapLeafHash::from_byte_array(crate::constructive::taproot::hash_tap_leaf(
            &script, 0xc0,
        ));
        let sighash = SighashCache::new(self.transaction())
            .taproot_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(prevout)),
                None,
                Some((leaf_hash, 0xffff_ffff)),
                TapSighashType::Default,
            )
            .map_err(|_| AssertionError::SighashFailed)?;
        Ok(sighash.to_byte_array())
    }

    /// Assembles the `Disprove` witness: `[signature, secret, script, control block]`.
    pub fn witness(&self, signature: [u8; 64]) -> Result<Witness, AssertionError> {
        Ok(Witness::from_slice(&[
            signature.to_vec(),
            self.secret.to_vec(),
            self.assertion.disprove_script(),
            self.assertion.disprove_control_block()?,
        ]))
    }

    /// Verifies an unsigned `Disprove` transaction against the assertion and a fee range.
    pub fn verify(
        transaction: &Transaction,
        assertion: &Assertion,
        anchor: AssertionAnchor,
        secret: [u8; DISCLOSURE_SECRET_LEN],
        destination_script: &ScriptBuf,
        bounds: FeeBounds,
    ) -> Result<Self, AssertionError> {
        if transaction.version != Version::TWO
            || transaction.lock_time != LockTime::ZERO
            || transaction.input.len() != 1
            || transaction.output.len() != 1
        {
            return Err(AssertionError::TransactionShapeMismatch);
        }
        if !transaction.input[0].witness.is_empty() {
            return Err(AssertionError::TransactionShapeMismatch);
        }
        if transaction.input[0].previous_output != anchor.outpoint
            || transaction.input[0].sequence != DISPROVE_INPUT_SEQUENCE
        {
            return Err(AssertionError::TransactionInputMismatch);
        }
        if transaction.output[0].script_pubkey != *destination_script {
            return Err(AssertionError::DestinationMismatch);
        }

        let fee_sats = anchor
            .value_sats
            .checked_sub(transaction.output[0].value.to_sat())
            .ok_or(AssertionError::OutputExceedsContested {
                contested_sats: anchor.value_sats,
                output_sats: transaction.output[0].value.to_sat(),
            })?;
        if !bounds.contains(fee_sats) {
            return Err(AssertionError::MinerFeeOutOfBounds {
                fee_sats,
                min_sats: bounds.min_sats,
                max_sats: bounds.max_sats,
            });
        }

        DisproveSpend::new(
            assertion,
            anchor,
            secret,
            destination_script.clone(),
            fee_sats,
        )
    }
}

/// Rejection reasons for the assertion edges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertionError {
    /// The statement digest is not a field-sized `CubeV1/Statement/v1` digest.
    StatementDigestNotFieldSized,
    /// A committed field is zero.
    ZeroField {
        /// The field name.
        field: &'static str,
    },
    /// The operator and beneficiary keys are the same key.
    RepeatedKey,
    /// The beneficiary key is zero.
    ZeroBeneficiaryKey,
    /// The challenge window cannot be encoded as a relative block height.
    InvalidChallengeWindow {
        /// The rejected window.
        blocks: u32,
    },
    /// The contested value is zero.
    ZeroContestedValue,
    /// The assertion taproot degenerated to an unspendable or invalid output key.
    TaprootDegenerate,
    /// The requested fee consumes the whole value.
    FeeExceedsValue {
        /// The value.
        value_sats: u64,
        /// The fee.
        fee_sats: u64,
    },
    /// The transaction's version, locktime, input/output count or witness state is wrong.
    TransactionShapeMismatch,
    /// The transaction spends something other than the anchored output, or changes its sequence.
    TransactionInputMismatch,
    /// The output does not pay the destination the caller named.
    DestinationMismatch,
    /// The output is worth more than the contested value.
    OutputExceedsContested {
        /// The contested value.
        contested_sats: u64,
        /// The output value.
        output_sats: u64,
    },
    /// The output script is not the assertion script for these terms.
    AssertionScriptMismatch,
    /// The anchor value and the assertion value disagree.
    AnchorValueMismatch {
        /// The assertion value.
        expected_sats: u64,
        /// The anchor value.
        anchor_sats: u64,
    },
    /// The miner fee lies outside the range the caller accepts.
    MinerFeeOutOfBounds {
        /// The fee.
        fee_sats: u64,
        /// The smallest accepted fee.
        min_sats: u64,
        /// The largest accepted fee.
        max_sats: u64,
    },
    /// The supplied secret does not open the disclosed commitment.
    WrongDisclosureSecret,
    /// The anchor is not the claim this assertion was built for.
    ClaimScriptMismatch,
    /// The sighash could not be computed.
    SighashFailed,
}

/// Returns the tagged digest of an assertion claim script, for fixture comparisons.
pub fn assertion_claim_script_digest(script: &[u8]) -> [u8; 32] {
    script.hash(Some(HashTag::CustomString(
        "CubeV1/AssertionClaimScript/v0".to_string(),
    )))
}
