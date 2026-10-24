//! Tests for the `FundSplit` relation: statement binding and the funding transition.
//!
//! The first test ties the circuit's hard-coded layout and host-side digests to the model's
//! encoding and to states the model actually produced. The rest synthesize constraints; the last
//! two build a *consistent but invalid* pair — digest binding satisfied, rule broken — so the
//! transition rules are tested rather than only the commitment.

mod common;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use common::{fixture, Fixture};
use cube_proof::fund_split::{
    statement_scalar, tagged_state_digest, tagged_statement_digest, FundSplitCircuit,
    ANCHOR_COUNT_OFFSET, KIND_BENEFICIARY_ALLOCATION, KIND_EXECUTION_FEE, MANIFEST_ENCODED_LEN,
    MANIFEST_RESULTING_STATE_DIGEST_OFFSET, PAYOUTS_OFFSET, PAYOUT_COUNT_OFFSET,
    PAYOUT_ENCODED_LEN, PHASE_ALLOCATED, PHASE_EMPTY, STATE_BOB_SHADOW_OFFSET,
    STATE_CAROL_SHADOW_OFFSET, STATE_CONTRACT_BALANCE_OFFSET, STATE_ENCODED_LEN,
    STATE_GROSS_OFFSET, STATE_INSTANCE_FLAG_OFFSET, STATE_INSTANCE_SEQUENCE_OFFSET,
    STATE_OWNER_SEQUENCE_OFFSET, STATE_PHASE_OFFSET, SUPPORTED_ANCHOR_COUNT,
    SUPPORTED_PAYOUT_COUNT,
};

/// Reads the amount of one payout out of the encoded manifest.
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

/// Reads a little-endian `u64` field of a state.
fn state_u64_at(state: &[u8], offset: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&state[offset..offset + 8]);
    u64::from_le_bytes(value)
}

/// Writes a little-endian `u64` field of a state.
fn set_state_u64(state: &mut [u8], offset: usize, value: u64) {
    state[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Synthesizes the circuit and reports whether the constraint system is satisfied.
fn is_satisfied(circuit: FundSplitCircuit) -> bool {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("constraint synthesis must not fail");
    cs.is_satisfied().expect("the system must be evaluable")
}

/// The honest witness for a fixture.
fn honest_for(fixture: &Fixture) -> FundSplitCircuit {
    FundSplitCircuit::from_parts(
        fixture.manifest_bytes(),
        fixture.previous_state.clone(),
        fixture.resulting_state.clone(),
        0,
    )
}

/// The honest witness of the default fixture.
fn honest() -> FundSplitCircuit {
    honest_for(&fixture())
}

/// Builds a circuit whose manifest commits `state` as its resulting state.
///
/// This keeps the digest binding satisfied while the transition itself is wrong, which is what a
/// malicious prover would try.
fn with_resulting_state(fixture: &Fixture, state: Vec<u8>) -> FundSplitCircuit {
    let mut bytes = fixture.manifest_bytes();
    let digest = tagged_state_digest(&state);
    bytes[MANIFEST_RESULTING_STATE_DIGEST_OFFSET..][..32].copy_from_slice(&digest);

    FundSplitCircuit::from_parts(bytes, fixture.previous_state.clone(), state, 0)
}

#[test]
fn layout_and_host_digests_match_the_model() {
    let fixture = fixture();
    let manifest = fixture.manifest_bytes();

    // 1 The circuit's fixed manifest offsets describe this encoding.
    assert_eq!(manifest.len(), MANIFEST_ENCODED_LEN);
    assert_eq!(manifest[ANCHOR_COUNT_OFFSET], SUPPORTED_ANCHOR_COUNT);
    assert_eq!(manifest[PAYOUT_COUNT_OFFSET], SUPPORTED_PAYOUT_COUNT);
    assert_eq!(amount_at(&manifest, 0), fixture.bob_sats);
    assert_eq!(amount_at(&manifest, 1), fixture.carol_sats);
    assert_eq!(amount_at(&manifest, 2), fixture.fee_sats);
    assert_eq!(manifest[kind_offset(0)], KIND_BENEFICIARY_ALLOCATION);
    assert_eq!(manifest[kind_offset(1)], KIND_BENEFICIARY_ALLOCATION);
    assert_eq!(manifest[kind_offset(2)], KIND_EXECUTION_FEE);

    // 2 The host-side statement digest is the model's, including the field-sizing mask.
    assert_eq!(
        tagged_statement_digest(&manifest),
        fixture.manifest.statement_digest()
    );
    assert_eq!(
        statement_scalar(&manifest),
        Fr::from_be_bytes_mod_order(&fixture.manifest.statement_digest())
    );

    // 3 The states are the model's, and the manifest commits their digests.
    assert_eq!(fixture.previous_state.len(), STATE_ENCODED_LEN);
    assert_eq!(fixture.resulting_state.len(), STATE_ENCODED_LEN);
    assert_eq!(
        tagged_state_digest(&fixture.previous_state),
        fixture.manifest.previous_state_digest
    );
    assert_eq!(
        tagged_state_digest(&fixture.resulting_state),
        fixture.manifest.resulting_state_digest
    );
    assert_eq!(
        manifest[MANIFEST_RESULTING_STATE_DIGEST_OFFSET..][..32],
        fixture.manifest.resulting_state_digest
    );

    // 4 The states hold the values the transition rules expect.
    assert_eq!(
        fixture.previous_state[STATE_INSTANCE_FLAG_OFFSET], 1,
        "the fixture state must have its instance"
    );
    assert_eq!(fixture.previous_state[STATE_PHASE_OFFSET], PHASE_EMPTY);
    assert_eq!(fixture.resulting_state[STATE_PHASE_OFFSET], PHASE_ALLOCATED);
    assert_eq!(
        state_u64_at(&fixture.resulting_state, STATE_GROSS_OFFSET),
        100_000
    );
    assert_eq!(
        state_u64_at(&fixture.resulting_state, STATE_CONTRACT_BALANCE_OFFSET),
        fixture.bob_sats + fixture.carol_sats
    );
    assert_eq!(
        state_u64_at(&fixture.resulting_state, STATE_BOB_SHADOW_OFFSET),
        fixture.bob_sats
    );
    assert_eq!(
        state_u64_at(&fixture.resulting_state, STATE_CAROL_SHADOW_OFFSET),
        fixture.carol_sats
    );
    assert_eq!(
        state_u64_at(&fixture.resulting_state, STATE_OWNER_SEQUENCE_OFFSET),
        state_u64_at(&fixture.previous_state, STATE_OWNER_SEQUENCE_OFFSET) + 1
    );
    assert_eq!(
        state_u64_at(&fixture.resulting_state, STATE_INSTANCE_SEQUENCE_OFFSET),
        state_u64_at(&fixture.previous_state, STATE_INSTANCE_SEQUENCE_OFFSET) + 1
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
    // Bob's allocation is exactly 70% of the distributable amount, so a nonzero remainder is false.
    let mut circuit = honest();
    circuit.remainder_bps = 1;
    assert!(!is_satisfied(circuit));
}

#[test]
fn a_tampered_manifest_is_rejected() {
    // Keep the honest public scalar and swap the witness: the field at byte 600 is hashed but not
    // otherwise constrained, so only the digest recomputation can catch it.
    let mut circuit = honest();
    circuit.manifest[600] ^= 0x01;
    assert!(!is_satisfied(circuit));
}

#[test]
fn a_tampered_state_is_rejected() {
    // The state is hashed, so any edit breaks the digest binding even when the rules would still
    // hold on the edited bytes.
    let mut circuit = honest();
    circuit.resulting_state[STATE_GROSS_OFFSET] ^= 0x01;
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
    let fixture = fixture();
    let mut bytes = fixture.manifest_bytes();
    bytes[ANCHOR_COUNT_OFFSET] = 2;
    assert!(!is_satisfied(FundSplitCircuit::from_parts(
        bytes,
        fixture.previous_state.clone(),
        fixture.resulting_state.clone(),
        0,
    )));
}

#[test]
fn a_wrong_payout_kind_is_rejected() {
    let fixture = fixture();
    let mut bytes = fixture.manifest_bytes();
    bytes[kind_offset(2)] = KIND_BENEFICIARY_ALLOCATION;
    assert!(!is_satisfied(FundSplitCircuit::from_parts(
        bytes,
        fixture.previous_state.clone(),
        fixture.resulting_state.clone(),
        0,
    )));
}

#[test]
fn a_contract_balance_that_does_not_match_the_payouts_is_rejected() {
    // The manifest commits the doctored state, so digest binding passes. Only the transition rule
    // can catch the one-satoshi discrepancy.
    let fixture = fixture();
    let mut state = fixture.resulting_state.clone();
    let balance = state_u64_at(&state, STATE_CONTRACT_BALANCE_OFFSET);
    set_state_u64(&mut state, STATE_CONTRACT_BALANCE_OFFSET, balance + 1);
    assert!(!is_satisfied(with_resulting_state(&fixture, state)));
}

#[test]
fn a_sequence_that_does_not_advance_is_rejected() {
    // Same trick: a consistent digest over a state whose owner sequence did not move.
    let fixture = fixture();
    let mut state = fixture.resulting_state.clone();
    let sequence = state_u64_at(&fixture.previous_state, STATE_OWNER_SEQUENCE_OFFSET);
    set_state_u64(&mut state, STATE_OWNER_SEQUENCE_OFFSET, sequence);
    assert!(!is_satisfied(with_resulting_state(&fixture, state)));
}
