//! The `FundSplit` relation: statement binding plus the funding transition.
//!
//! The circuit proves three things about one accepted `FundSplit`:
//!
//! 1. **The statement is committed.** It recomputes the tagged SHA-256 digest of the 629-byte
//!    manifest in-circuit, truncates it to the scalar field exactly as `CubeV1/Statement/v1` does,
//!    and requires the result to equal the public scalar.
//! 2. **Both states are the committed ones.** The manifest commits a previous and a resulting state
//!    digest. The circuit recomputes each tagged state digest from the 343-byte state preimages and
//!    compares them with those committed bytes, so a prover cannot present states the manifest does
//!    not describe.
//! 3. **The funding transition is valid.** Reading both states directly:
//!    - the phase moves from `EMPTY` to `ALLOCATED`;
//!    - the destination, contract identity and descriptor are unchanged;
//!    - before funding the gross, execution fee, contract balance and both shadows are zero;
//!    - after funding `gross = B + C + E`, `execution_fee = E` and `contract_balance = B + C`;
//!    - the owner is debited `B + C + E`, the fee account is credited `E`, and the beneficiaries'
//!      native balances do not move;
//!    - the owner sequence and the instance sequence advance by exactly one, and no other sequence
//!      changes;
//!    - finally `B` is the floor of `(B + C) * 7 / 10`, with the remainder witness in range.
//!
//! # The layout this circuit commits to
//!
//! The manifest encoding has a variable number of anchors, which moves every later field, and the
//! state encoding has an optional instance block. Rather than index dynamically, this circuit
//! version fixes both shapes:
//!
//! ```text
//! manifest: 1 anchor, 3 payouts -> 629 bytes, payouts at 344, state digests at 130 and 162
//! state:    instance present   -> 343 bytes
//! ```
//!
//! The anchor count, payout count and instance flags are constrained as well as used, so a
//! differently shaped object cannot slip past the fixed offsets. Another shape needs another
//! circuit id, verifying key and vectors.
//!
//! # Measured size
//!
//! 906,353 constraints for this shape in a debug build: eleven SHA-256 blocks for the manifest and
//! seven for each state preimage. Synthesis takes roughly 25 seconds per instance in a debug build.
//! A release Groth16 setup takes about 6.7 s and a proof about 4.3 s; the garbled table does not
//! grow with the constraint count because it depends only on the verifying key.
//!
//! # What this circuit does not prove
//!
//! - **Replay protection.** The consumed-operation set is unbounded and is not committed by the
//!   state digest, so the circuit cannot show that this operation id was unused.
//! - **Authorization.** The caller signature is not checked. BIP-340 inside BN254 is a separate
//!   gadget and is not implemented.
//! - **Contract execution.** The CubeVM program's own arithmetic and the payouts' recipient keys are
//!   covered only through the digests.
//! - **Anything on chain.** The public scalar is assumed to come from an authenticated Bitcoin
//!   output. This crate never reads a chain, and the setup is a single-party test setup.

use ark_bn254::Fr;
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::cmp::CmpGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::uint64::UInt64;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use sha2::{Digest, Sha256};

/// The tagged-hash tag of the statement commitment.
///
/// Must match `cube::model::fixed_split_vault_v1::manifest::STATEMENT_DIGEST_TAG`; a test asserts
/// the whole digest, which fails if either side moves.
pub const STATEMENT_TAG: &str = "CubeV1/Statement/v1";

/// The tagged-hash tag of a committed state.
///
/// Must match `cube::model::fixed_split_vault_v1::codec::STATE_DIGEST_TAG`.
pub const STATE_TAG: &str = "CubeV1/State/v0";

/// The bits of the most significant digest byte that survive field-sizing.
const STATEMENT_DIGEST_TOP_BYTE_MASK: u8 = 0x1f;

/// The encoded length of a manifest with one anchor and three payouts.
pub const MANIFEST_ENCODED_LEN: usize = 629;

/// The anchor count byte of the canonical encoding.
pub const ANCHOR_COUNT_OFFSET: usize = 202;

/// The only anchor count this circuit version supports.
pub const SUPPORTED_ANCHOR_COUNT: u8 = 1;

/// The payout count byte of the canonical encoding, for this anchor count.
pub const PAYOUT_COUNT_OFFSET: usize = 343;

/// The first payout of the canonical encoding, for this anchor count.
pub const PAYOUTS_OFFSET: usize = 344;

/// The encoded length of one payout: recipient key, amount, kind.
pub const PAYOUT_ENCODED_LEN: usize = 41;

/// The only payout count this circuit version supports.
pub const SUPPORTED_PAYOUT_COUNT: u8 = 3;

/// The number of beneficiary allocations, in manifest order.
pub const BENEFICIARY_PAYOUTS: usize = 2;

const PAYOUT_AMOUNT_OFFSET: usize = 32;
const PAYOUT_KIND_OFFSET: usize = 40;
const PAYOUT_AMOUNT_LEN: usize = 8;

/// The payout kind tag of a beneficiary allocation.
pub const KIND_BENEFICIARY_ALLOCATION: u8 = 0x00;
/// The payout kind tag of the disclosed execution fee.
pub const KIND_EXECUTION_FEE: u8 = 0x01;

/// The basis-point denominator of the split.
pub const BPS_DENOMINATOR: u64 = 10_000;
/// Bob's weight in basis points; Carol receives the remainder.
pub const BENEFICIARY_WEIGHT_BPS: u64 = 7_000;

/// The offset of the previous state digest inside the manifest.
pub const MANIFEST_PREVIOUS_STATE_DIGEST_OFFSET: usize = 130;

/// The offset of the resulting state digest inside the manifest.
pub const MANIFEST_RESULTING_STATE_DIGEST_OFFSET: usize = 162;

/// The encoded length of a state with its instance present.
pub const STATE_ENCODED_LEN: usize = 343;

/// The instance presence flag of the state encoding.
pub const STATE_INSTANCE_FLAG_OFFSET: usize = 1;

/// The descriptor block of the state encoding.
pub const STATE_DESCRIPTOR_OFFSET: usize = 2;
/// The length of the descriptor block.
pub const DESCRIPTOR_LEN: usize = 196;

/// The contract identity block of the state encoding.
pub const STATE_CONTRACT_ID_OFFSET: usize = 198;
/// The length of the contract identity.
pub const CONTRACT_ID_LEN: usize = 32;

/// The gross amount of the instance.
pub const STATE_GROSS_OFFSET: usize = 230;
/// The disclosed execution fee of the instance.
pub const STATE_EXECUTION_FEE_OFFSET: usize = 238;
/// The lifecycle phase tag.
pub const STATE_PHASE_OFFSET: usize = 246;
/// The contract balance backing the shadows.
pub const STATE_CONTRACT_BALANCE_OFFSET: usize = 247;
/// Bob's shadow allocation.
pub const STATE_BOB_SHADOW_OFFSET: usize = 255;
/// Carol's shadow allocation.
pub const STATE_CAROL_SHADOW_OFFSET: usize = 263;
/// The instance sequence.
pub const STATE_INSTANCE_SEQUENCE_OFFSET: usize = 271;
/// The owner's native balance.
pub const STATE_OWNER_BALANCE_OFFSET: usize = 279;
/// Bob's native balance.
pub const STATE_BOB_BALANCE_OFFSET: usize = 287;
/// Carol's native balance.
pub const STATE_CAROL_BALANCE_OFFSET: usize = 295;
/// The fee account's native balance.
pub const STATE_FEE_BALANCE_OFFSET: usize = 303;
/// The owner's caller sequence.
pub const STATE_OWNER_SEQUENCE_OFFSET: usize = 311;
/// Bob's caller sequence.
pub const STATE_BOB_SEQUENCE_OFFSET: usize = 319;
/// Carol's caller sequence.
pub const STATE_CAROL_SEQUENCE_OFFSET: usize = 327;
/// The fee account's caller sequence.
pub const STATE_FEE_SEQUENCE_OFFSET: usize = 335;

/// The phase tag before funding.
pub const PHASE_EMPTY: u8 = 0x00;
/// The phase tag after funding.
pub const PHASE_ALLOCATED: u8 = 0x01;

/// Recomputes the field-sized statement digest of `manifest`, host-side.
///
/// BIP-340 tagged hashing: `SHA256(SHA256(tag) || SHA256(tag) || manifest)`, then the three most
/// significant bits cleared. This must agree with `TransitionManifest::statement_digest`; a test
/// compares them on a manifest built by the model.
pub fn tagged_statement_digest(manifest: &[u8]) -> [u8; 32] {
    let mut digest = tagged_digest(STATEMENT_TAG, manifest);
    digest[0] &= STATEMENT_DIGEST_TOP_BYTE_MASK;
    digest
}

/// Recomputes the tagged digest of `state` without field-sizing.
///
/// Must agree with `SplitState::digest`; a test compares them on states built by the model.
pub fn tagged_state_digest(state: &[u8]) -> [u8; 32] {
    tagged_digest(STATE_TAG, state)
}

/// Host-side BIP-340 tagged hash.
fn tagged_digest(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(message);
    hasher.finalize().into()
}

/// Returns the public scalar of `manifest`, which is the digest read as a big-endian integer.
///
/// Safe to convert without reduction because the digest is field-sized by construction.
pub fn statement_scalar(manifest: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(&tagged_statement_digest(manifest))
}

/// The `FundSplit` statement and its witness.
#[derive(Clone)]
pub struct FundSplitCircuit {
    /// The public scalar. It must be the statement digest, not a value derived from the witness.
    pub statement: Fr,
    /// The 629 canonical manifest bytes.
    pub manifest: Vec<u8>,
    /// The 343 canonical bytes of the state before funding.
    pub previous_state: Vec<u8>,
    /// The 343 canonical bytes of the state after funding.
    pub resulting_state: Vec<u8>,
    /// The quotient/remainder witness of Bob's floor division, in basis points.
    pub remainder_bps: u64,
}

impl FundSplitCircuit {
    /// Builds the circuit for a manifest and its two states, computing the public scalar.
    ///
    /// Intended for tests and for an honest prover: the whole point of the relation is that the
    /// public scalar is the digest of the manifest. A verifier never calls this.
    pub fn from_parts(
        manifest: Vec<u8>,
        previous_state: Vec<u8>,
        resulting_state: Vec<u8>,
        remainder_bps: u64,
    ) -> Self {
        let statement = statement_scalar(&manifest);
        Self {
            statement,
            manifest,
            previous_state,
            resulting_state,
            remainder_bps,
        }
    }
}

impl ConstraintSynthesizer<Fr> for FundSplitCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 1 The circuit's fixed offsets only describe these encoding shapes.
        if self.manifest.len() != MANIFEST_ENCODED_LEN
            || self.previous_state.len() != STATE_ENCODED_LEN
            || self.resulting_state.len() != STATE_ENCODED_LEN
        {
            return Err(SynthesisError::Unsatisfiable);
        }

        // 2 The public scalar. It is allocated from the statement, never from the witness.
        let statement = FpVar::new_input(cs.clone(), || Ok(self.statement))?;

        // 3 The manifest and both states are witness data.
        let manifest = witness_bytes(cs.clone(), &self.manifest)?;
        let previous = witness_bytes(cs.clone(), &self.previous_state)?;
        let resulting = witness_bytes(cs.clone(), &self.resulting_state)?;

        // 4 Pin the shapes the offsets assume.
        manifest[ANCHOR_COUNT_OFFSET].enforce_equal(&UInt8::constant(SUPPORTED_ANCHOR_COUNT))?;
        manifest[PAYOUT_COUNT_OFFSET].enforce_equal(&UInt8::constant(SUPPORTED_PAYOUT_COUNT))?;
        previous[STATE_INSTANCE_FLAG_OFFSET].enforce_equal(&UInt8::constant(1))?;
        resulting[STATE_INSTANCE_FLAG_OFFSET].enforce_equal(&UInt8::constant(1))?;

        // 5 The statement: recompute the tagged digest and compare it with the public scalar.
        //   Field-sizing drops the three most significant bits; the byte vector is big-endian, so
        //   reading it backwards gives little-endian bits and truncation applies the mask.
        let digest = tagged_digest_in_circuit(STATEMENT_TAG, &manifest)?;
        let mut digest_bits_le = Vec::with_capacity(253);
        for byte in digest.iter().rev() {
            digest_bits_le.extend_from_slice(&byte.bits);
        }
        digest_bits_le.truncate(253);
        Boolean::le_bits_to_fp(&digest_bits_le)?.enforce_equal(&statement)?;

        // 6 Both states must be the ones the manifest commits to.
        enforce_digest(
            &previous,
            &manifest[MANIFEST_PREVIOUS_STATE_DIGEST_OFFSET..][..32],
        )?;
        enforce_digest(
            &resulting,
            &manifest[MANIFEST_RESULTING_STATE_DIGEST_OFFSET..][..32],
        )?;

        // 7 The payout kinds, in manifest order.
        let payout_offset = |index: usize| PAYOUTS_OFFSET + index * PAYOUT_ENCODED_LEN;
        for index in 0..BENEFICIARY_PAYOUTS {
            manifest[payout_offset(index) + PAYOUT_KIND_OFFSET]
                .enforce_equal(&UInt8::constant(KIND_BENEFICIARY_ALLOCATION))?;
        }
        manifest[payout_offset(BENEFICIARY_PAYOUTS) + PAYOUT_KIND_OFFSET]
            .enforce_equal(&UInt8::constant(KIND_EXECUTION_FEE))?;

        // 8 The amounts, read from the committed bytes. The canonical encoding is little-endian.
        let amount_at = |index: usize| -> Result<UInt64<Fr>, SynthesisError> {
            let start = payout_offset(index) + PAYOUT_AMOUNT_OFFSET;
            UInt64::from_bytes_le(&manifest[start..start + PAYOUT_AMOUNT_LEN])
        };
        let bob = amount_at(0)?;
        let carol = amount_at(1)?;
        let fee = amount_at(BENEFICIARY_PAYOUTS)?;

        // 9 Every amount is nonzero, and the remainder witness is a real basis-point remainder.
        for amount in [&bob, &carol, &fee] {
            amount
                .is_gt(&UInt64::constant(0))?
                .enforce_equal(&Boolean::TRUE)?;
        }
        let remainder = UInt64::new_witness(cs.clone(), || Ok(self.remainder_bps))?;
        remainder
            .is_lt(&UInt64::constant(BPS_DENOMINATOR))?
            .enforce_equal(&Boolean::TRUE)?;

        // 10 `B = floor((B + C) * 7000 / 10000)` as `(B + C) * 7000 = B * 10000 + rem`.
        //    The products are at most 66 bits, so field arithmetic is exact here.
        let bob_fp = bob.to_fp()?;
        let carol_fp = carol.to_fp()?;
        let fee_fp = fee.to_fp()?;
        let distributable = &bob_fp + &carol_fp;
        let weighted = &distributable * FpVar::constant(Fr::from(BENEFICIARY_WEIGHT_BPS));
        let allocated =
            &bob_fp * FpVar::constant(Fr::from(BPS_DENOMINATOR)) + &remainder.to_fp()?;
        weighted.enforce_equal(&allocated)?;

        // 11 The funding transition itself.
        // 11.1 EMPTY becomes ALLOCATED.
        previous[STATE_PHASE_OFFSET].enforce_equal(&UInt8::constant(PHASE_EMPTY))?;
        resulting[STATE_PHASE_OFFSET].enforce_equal(&UInt8::constant(PHASE_ALLOCATED))?;

        // 11.2 The instance identity cannot change.
        enforce_bytes_equal(
            &previous[STATE_DESCRIPTOR_OFFSET..][..DESCRIPTOR_LEN],
            &resulting[STATE_DESCRIPTOR_OFFSET..][..DESCRIPTOR_LEN],
        )?;
        enforce_bytes_equal(
            &previous[STATE_CONTRACT_ID_OFFSET..][..CONTRACT_ID_LEN],
            &resulting[STATE_CONTRACT_ID_OFFSET..][..CONTRACT_ID_LEN],
        )?;

        // 11.3 Before funding there is no gross, no fee, no contract balance and no shadow.
        for offset in [
            STATE_GROSS_OFFSET,
            STATE_EXECUTION_FEE_OFFSET,
            STATE_CONTRACT_BALANCE_OFFSET,
            STATE_BOB_SHADOW_OFFSET,
            STATE_CAROL_SHADOW_OFFSET,
        ] {
            state_u64(&previous, offset)?.enforce_equal(&zero()?)?;
        }

        // 11.4 After funding the instance records exactly what the payouts authorise.
        let gross = &distributable + &fee_fp;
        state_u64(&resulting, STATE_GROSS_OFFSET)?.enforce_equal(&gross)?;
        state_u64(&resulting, STATE_EXECUTION_FEE_OFFSET)?.enforce_equal(&fee_fp)?;
        state_u64(&resulting, STATE_CONTRACT_BALANCE_OFFSET)?.enforce_equal(&distributable)?;
        state_u64(&resulting, STATE_BOB_SHADOW_OFFSET)?.enforce_equal(&bob_fp)?;
        state_u64(&resulting, STATE_CAROL_SHADOW_OFFSET)?.enforce_equal(&carol_fp)?;

        // 11.5 The owner is debited the gross and the fee account is credited the fee. An owner
        //    balance below the gross cannot satisfy the equality because the result is a 64-bit
        //    value.
        let owner_after = &state_u64(&previous, STATE_OWNER_BALANCE_OFFSET)? - &gross;
        owner_after.enforce_equal(&state_u64(&resulting, STATE_OWNER_BALANCE_OFFSET)?)?;
        (&state_u64(&previous, STATE_FEE_BALANCE_OFFSET)? + &fee_fp)
            .enforce_equal(&state_u64(&resulting, STATE_FEE_BALANCE_OFFSET)?)?;

        // 11.6 The beneficiaries' native balances do not move in this transition.
        state_u64(&previous, STATE_BOB_BALANCE_OFFSET)?
            .enforce_equal(&state_u64(&resulting, STATE_BOB_BALANCE_OFFSET)?)?;
        state_u64(&previous, STATE_CAROL_BALANCE_OFFSET)?
            .enforce_equal(&state_u64(&resulting, STATE_CAROL_BALANCE_OFFSET)?)?;

        // 11.7 The owner sequence and the instance sequence advance by exactly one. Every other
        //    sequence is untouched.
        let one = FpVar::constant(Fr::from(1u64));
        (&state_u64(&previous, STATE_OWNER_SEQUENCE_OFFSET)? + &one)
            .enforce_equal(&state_u64(&resulting, STATE_OWNER_SEQUENCE_OFFSET)?)?;
        (&state_u64(&previous, STATE_INSTANCE_SEQUENCE_OFFSET)? + &one)
            .enforce_equal(&state_u64(&resulting, STATE_INSTANCE_SEQUENCE_OFFSET)?)?;
        for offset in [
            STATE_BOB_SEQUENCE_OFFSET,
            STATE_CAROL_SEQUENCE_OFFSET,
            STATE_FEE_SEQUENCE_OFFSET,
        ] {
            state_u64(&previous, offset)?.enforce_equal(&state_u64(&resulting, offset)?)?;
        }

        Ok(())
    }
}

/// Allocates a byte string as witness data.
fn witness_bytes(
    cs: ConstraintSystemRef<Fr>,
    bytes: &[u8],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    bytes
        .iter()
        .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
        .collect()
}

/// Recomputes a tagged digest over `message` in-circuit.
fn tagged_digest_in_circuit(
    tag: &str,
    message: &[UInt8<Fr>],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let tag_hash = Sha256::digest(tag.as_bytes());

    let mut preimage = Vec::with_capacity(64 + message.len());
    for _ in 0..2 {
        for byte in tag_hash.iter() {
            preimage.push(UInt8::constant(*byte));
        }
    }
    preimage.extend(message.iter().cloned());

    Ok(Sha256Gadget::digest(&preimage)?.0)
}

/// Requires the tagged digest of `state` to equal `expected`.
fn enforce_digest(state: &[UInt8<Fr>], expected: &[UInt8<Fr>]) -> Result<(), SynthesisError> {
    let digest = tagged_digest_in_circuit(STATE_TAG, state)?;
    enforce_bytes_equal(&digest, expected)
}

/// Requires two byte strings to be identical.
fn enforce_bytes_equal(a: &[UInt8<Fr>], b: &[UInt8<Fr>]) -> Result<(), SynthesisError> {
    if a.len() != b.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    for (left, right) in a.iter().zip(b) {
        left.enforce_equal(right)?;
    }
    Ok(())
}

/// Reads a little-endian `u64` field of a state as a field element.
fn state_u64(state: &[UInt8<Fr>], offset: usize) -> Result<FpVar<Fr>, SynthesisError> {
    UInt64::from_bytes_le(&state[offset..offset + 8])?.to_fp()
}

/// The field zero.
fn zero() -> Result<FpVar<Fr>, SynthesisError> {
    Ok(FpVar::constant(Fr::from(0u64)))
}
