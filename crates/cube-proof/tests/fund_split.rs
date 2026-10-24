//! Tests for the `FundSplit` statement binding.
//!
//! The first test is the important one: it ties the circuit's hard-coded layout and host-side digest
//! to the model's canonical encoding. Everything after it synthesizes constraints, so if the layout
//! drifts the failure points at the model rather than at a magic offset.

mod common;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use cube_proof::fund_split::{
    statement_scalar, tagged_statement_digest, FundSplitCircuit, ANCHOR_COUNT_OFFSET,
    KIND_BENEFICIARY_ALLOCATION, KIND_EXECUTION_FEE, MANIFEST_ENCODED_LEN, PAYOUTS_OFFSET,
    PAYOUT_COUNT_OFFSET, PAYOUT_ENCODED_LEN, SUPPORTED_ANCHOR_COUNT, SUPPORTED_PAYOUT_COUNT,
};

use common::{manifest, manifest_bytes, BOB_SATS, CAROL_SATS, FEE_SATS};

/// Reads the amount of one payout out of the encoded bytes.
///
/// The canonical encoding stores integers little-endian.
fn amount_at(bytes: &[u8], index: usize) -> u64 {
    let start = PAYOUTS_OFFSET + index * PAYOUT_ENCODED_LEN + 32;
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[start..start + 8]);
    u64::from_le_bytes(value)
}

/// Returns the byte offset of one payout's kind tag.
fn kind_offset(index: usize) -> usize {
    PAYOUTS_OFFSET + index * PAYOUT_ENCODED_LEN + 40
}

/// Synthesizes the circuit and reports whether the constraint system is satisfied.
fn is_satisfied(circuit: FundSplitCircuit) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("constraint synthesis must not fail");
    cs.is_satisfied().expect("the system must be evaluable")
}

/// The honest witness: Bob 70 000, Carol 30 000, so the remainder is zero.
fn honest() -> FundSplitCircuit {
    FundSplitCircuit::from_manifest(manifest_bytes(), 0)
}

#[test]
fn layout_and_host_digest_match_the_model() {
    let model_manifest = manifest();
    let bytes = model_manifest.encode();

    // 1 The circuit's fixed offsets describe this encoding.
    assert_eq!(bytes.len(), MANIFEST_ENCODED_LEN);
    assert_eq!(bytes[ANCHOR_COUNT_OFFSET], SUPPORTED_ANCHOR_COUNT);
    assert_eq!(bytes[PAYOUT_COUNT_OFFSET], SUPPORTED_PAYOUT_COUNT);

    // 2 The payouts the circuit reads are the payouts the model wrote.
    assert_eq!(amount_at(&bytes, 0), BOB_SATS);
    assert_eq!(amount_at(&bytes, 1), CAROL_SATS);
    assert_eq!(amount_at(&bytes, 2), FEE_SATS);
    assert_eq!(bytes[kind_offset(0)], KIND_BENEFICIARY_ALLOCATION);
    assert_eq!(bytes[kind_offset(1)], KIND_BENEFICIARY_ALLOCATION);
    assert_eq!(bytes[kind_offset(2)], KIND_EXECUTION_FEE);

    // 3 The host-side digest is the model's digest, including the field-sizing mask.
    assert_eq!(
        tagged_statement_digest(&bytes),
        model_manifest.statement_digest()
    );
    assert_eq!(
        statement_scalar(&bytes),
        Fr::from_be_bytes_mod_order(&model_manifest.statement_digest())
    );
}

#[test]
fn honest_witness_satisfies_the_constraints() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    honest()
        .generate_constraints(cs.clone())
        .expect("synthesis");
    println!("fund_split constraints: {}", cs.num_constraints());
    assert!(cs.is_satisfied().expect("evaluable"));
}

#[test]
fn a_wrong_remainder_is_rejected() {
    // Bob's allocation is exactly 70% of 100 000, so any nonzero remainder is a false witness.
    let mut circuit = honest();
    circuit.remainder_bps = 1;
    assert!(!is_satisfied(circuit));
}

#[test]
fn a_tampered_manifest_is_rejected() {
    // Keep the honest public scalar and swap the witness: this is the binding test. The field at
    // byte 600 (the availability descriptor) is hashed but not otherwise constrained, so only the
    // digest recomputation can catch it.
    let mut circuit = honest();
    circuit.manifest[600] ^= 0x01;
    assert!(!is_satisfied(circuit));
}

#[test]
fn a_wrong_public_scalar_is_rejected() {
    let mut circuit = honest();
    circuit.statement += Fr::from(1u64);
    assert!(!is_satisfied(circuit));
}

#[test]
fn a_different_manifest_shape_is_rejected() {
    // Two anchors move every later field, so the fixed offsets no longer describe the encoding.
    let mut bytes = manifest_bytes();
    bytes[ANCHOR_COUNT_OFFSET] = 2;
    assert!(!is_satisfied(FundSplitCircuit::from_manifest(bytes, 0)));
}

#[test]
fn a_wrong_payout_kind_is_rejected() {
    let mut bytes = manifest_bytes();
    bytes[kind_offset(2)] = KIND_BENEFICIARY_ALLOCATION;
    assert!(!is_satisfied(FundSplitCircuit::from_manifest(bytes, 0)));
}
