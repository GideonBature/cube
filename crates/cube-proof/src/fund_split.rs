//! The `FundSplit` statement binding.
//!
//! This circuit proves two things about the 629-byte canonical manifest of a `FundSplit`
//! transition, and nothing else:
//!
//! 1. **The statement is committed.** It recomputes the tagged SHA-256 digest of the manifest
//!    in-circuit, truncates it to the scalar field exactly as `CubeV1/Statement/v1` does, and
//!    requires the result to equal the public scalar.
//! 2. **The split obligations hold.** It reads the three payout amounts out of the committed bytes
//!    and requires `(B + C) * 7000 == B * 10000 + rem` with `rem < 10000`, so `B` is the floor of
//!    `(B + C) * 7 / 10` and Carol's allocation is the remainder. Both beneficiary kinds are
//!    checked, and every amount must be nonzero.
//!
//! # The layout this circuit commits to
//!
//! The manifest encoding has a variable number of anchors, which moves every later field. Rather
//! than index dynamically, this circuit version fixes the shape:
//!
//! ```text
//! anchors       = 1   (the funding outpoint)
//! payouts       = 3   (Bob allocation, Carol allocation, execution fee)
//! encoded length = 629 bytes
//! payouts start  = 344
//! ```
//!
//! The anchor count and payout count bytes are constrained as well as used, so a manifest with a
//! different shape cannot slip past the fixed offsets. A statement with two anchors or a different
//! payout count needs a different circuit id, its own verifying key and its own vectors.
//!
//! # What this circuit does not prove
//!
//! - **State-transition validity.** Balances, caller sequences, replay protection, the contract's
//!   own phase and the execution fee deduction are not constrained. The circuit proves a property
//!   of the committed statement, not that the engine executed anything correctly.
//! - **Authorization.** The caller signature is not checked. BIP-340 inside BN254 is a separate
//!   gadget and is not implemented.
//! - **Recipient binding beyond the digest.** The payout keys are covered by the digest; they are
//!   not otherwise constrained.
//! - **Anything on chain.** The public scalar is assumed to come from an authenticated Bitcoin
//!   output. This crate never reads a chain, and no verifying key or proof is generated yet.

use ark_bn254::Fr;
use ark_crypto_primitives::crh::sha256::constraints::{DigestVar, Sha256Gadget};
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

/// Recomputes the field-sized statement digest of `manifest`, host-side.
///
/// BIP-340 tagged hashing: `SHA256(SHA256(tag) || SHA256(tag) || manifest)`, then the three most
/// significant bits cleared. This must agree with `TransitionManifest::statement_digest`; a test
/// compares them on a manifest built by the model.
pub fn tagged_statement_digest(manifest: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(STATEMENT_TAG.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(manifest);
    let mut digest: [u8; 32] = hasher.finalize().into();

    digest[0] &= STATEMENT_DIGEST_TOP_BYTE_MASK;
    digest
}

/// Returns the public scalar of `manifest`, which is the digest read as a big-endian integer.
///
/// Safe to reduce-less convert because the digest is field-sized by construction.
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
    /// The quotient/remainder witness of Bob's floor division, in basis points.
    pub remainder_bps: u64,
}

impl FundSplitCircuit {
    /// Builds the circuit for `manifest`, computing the public scalar from it.
    ///
    /// Intended for tests and for an honest prover: the whole point of the relation is that the
    /// public scalar is the digest of the witness. A verifier never calls this.
    pub fn from_manifest(manifest: Vec<u8>, remainder_bps: u64) -> Self {
        let statement = statement_scalar(&manifest);
        Self {
            statement,
            manifest,
            remainder_bps,
        }
    }
}

impl ConstraintSynthesizer<Fr> for FundSplitCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 1 The circuit's fixed offsets only describe one encoding shape.
        if self.manifest.len() != MANIFEST_ENCODED_LEN {
            return Err(SynthesisError::Unsatisfiable);
        }

        // 2 The public scalar. It is allocated from the statement, never from the witness.
        let statement = FpVar::new_input(cs.clone(), || Ok(self.statement))?;

        // 3 The manifest is witness data.
        let bytes = self
            .manifest
            .iter()
            .map(|byte| UInt8::new_witness(cs.clone(), || Ok(*byte)))
            .collect::<Result<Vec<_>, _>>()?;

        // 4 Pin the shape the offsets assume, so a differently shaped manifest cannot be decoded
        //   at the wrong positions.
        bytes[ANCHOR_COUNT_OFFSET].enforce_equal(&UInt8::constant(SUPPORTED_ANCHOR_COUNT))?;
        bytes[PAYOUT_COUNT_OFFSET].enforce_equal(&UInt8::constant(SUPPORTED_PAYOUT_COUNT))?;

        // 5 Recompute the tagged digest in-circuit.
        let tag_hash = Sha256::digest(STATEMENT_TAG.as_bytes());
        let mut preimage = Vec::with_capacity(64 + bytes.len());
        for _ in 0..2 {
            for byte in tag_hash.iter() {
                preimage.push(UInt8::constant(*byte));
            }
        }
        preimage.extend(bytes.iter().cloned());
        let digest: DigestVar<Fr> = Sha256Gadget::digest(&preimage)?;

        // 6 Field-size the digest by dropping the three most significant bits. The byte vector is
        //   big-endian, so reading it backwards gives little-endian bits; truncating to 253 bits
        //   removes exactly the bits the mask clears.
        let mut digest_bits_le = Vec::with_capacity(253);
        for byte in digest.0.iter().rev() {
            digest_bits_le.extend_from_slice(&byte.bits);
        }
        digest_bits_le.truncate(253);
        let digest_field = Boolean::le_bits_to_fp(&digest_bits_le)?;
        digest_field.enforce_equal(&statement)?;

        // 7 The payout kinds, in manifest order.
        let payout_offset = |index: usize| PAYOUTS_OFFSET + index * PAYOUT_ENCODED_LEN;
        for index in 0..BENEFICIARY_PAYOUTS {
            bytes[payout_offset(index) + PAYOUT_KIND_OFFSET]
                .enforce_equal(&UInt8::constant(KIND_BENEFICIARY_ALLOCATION))?;
        }
        bytes[payout_offset(BENEFICIARY_PAYOUTS) + PAYOUT_KIND_OFFSET]
            .enforce_equal(&UInt8::constant(KIND_EXECUTION_FEE))?;

        // 8 The amounts, read from the committed bytes rather than supplied separately. The
        //   canonical encoding stores integers little-endian.
        let amount_at = |index: usize| -> Result<UInt64<Fr>, SynthesisError> {
            let start = payout_offset(index) + PAYOUT_AMOUNT_OFFSET;
            UInt64::from_bytes_le(&bytes[start..start + PAYOUT_AMOUNT_LEN])
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
        let distributable = &bob_fp + &carol_fp;
        let weighted = &distributable * FpVar::constant(Fr::from(BENEFICIARY_WEIGHT_BPS));
        let allocated =
            &bob_fp * FpVar::constant(Fr::from(BPS_DENOMINATOR)) + &remainder.to_fp()?;
        weighted.enforce_equal(&allocated)?;

        Ok(())
    }
}
