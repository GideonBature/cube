//! Tests for the Groth16 key conversion.
//!
//! The fixtures live in `common`: they are algebraic, not cryptographic. A fixture that satisfies
//! the identity is still **not** an execution proof for any relation.

mod common;

use ark_bn254::{Fq12, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use cube_argo::{ArgoAdapterError, Groth16VerifyingKey, PreparedVerifierKey};

use common::{canonical_identity_holds, fixture};

#[test]
fn converted_key_accepts_a_proof_the_canonical_identity_accepts() {
    let (key, proof) = fixture(11, Fr::from(5u64));
    assert!(
        canonical_identity_holds(&key, &proof),
        "the fixture must satisfy the canonical identity"
    );

    let prepared = PreparedVerifierKey::from_groth16_verifying_key(&key).expect("convert");
    assert_eq!(
        prepared.equation_value(&proof).expect("evaluate"),
        Fq12::ONE
    );
}

#[test]
fn converted_key_rejects_a_proof_for_a_different_public_scalar() {
    let x = Fr::from(5u64);
    let (key, proof) = fixture(21, x);
    let prepared = PreparedVerifierKey::from_groth16_verifying_key(&key).expect("convert");
    assert_eq!(
        prepared.equation_value(&proof).expect("evaluate"),
        Fq12::ONE
    );

    // The proof itself is untouched; only the scalar it is checked against moves. A key that
    // ignored `x` would still accept here.
    let mut shifted = proof;
    shifted.x = x + Fr::from(1u64);
    assert!(!canonical_identity_holds(&key, &shifted));
    assert_ne!(
        prepared.equation_value(&shifted).expect("evaluate"),
        Fq12::ONE
    );
}

#[test]
fn converted_key_rejects_tampered_proof_elements() {
    let (key, proof) = fixture(31, Fr::from(13u64));
    let prepared = PreparedVerifierKey::from_groth16_verifying_key(&key).expect("convert");

    let mut moved_c = proof;
    moved_c.c = (moved_c.c.into_group() + G1Affine::generator()).into_affine();
    assert!(!canonical_identity_holds(&key, &moved_c));
    assert_ne!(
        prepared.equation_value(&moved_c).expect("evaluate"),
        Fq12::ONE
    );

    let mut negated_b = proof;
    negated_b.b = (-negated_b.b.into_group()).into_affine();
    assert!(!canonical_identity_holds(&key, &negated_b));
    assert_ne!(
        prepared.equation_value(&negated_b).expect("evaluate"),
        Fq12::ONE
    );
}

#[test]
fn fixed_input_term_changes_the_key_and_invalidates_the_proof() {
    let (key, proof) = fixture(41, Fr::from(17u64));
    let prepared = PreparedVerifierKey::from_groth16_verifying_key(&key).expect("convert");
    assert_eq!(
        prepared.equation_value(&proof).expect("evaluate"),
        Fq12::ONE
    );

    // `ic[0]` carries no proof element, so it has to reach the verifier constant. If it were
    // dropped, the same proof would stay valid under the moved key.
    let mut moved = key.clone();
    moved.gamma_abc_g1[0] =
        (moved.gamma_abc_g1[0].into_group() + G1Affine::generator()).into_affine();
    let moved_prepared = PreparedVerifierKey::from_groth16_verifying_key(&moved).expect("convert");

    assert_ne!(moved_prepared.identity(), prepared.identity());
    assert_ne!(
        moved_prepared.equation_value(&proof).expect("evaluate"),
        Fq12::ONE
    );
}

#[test]
fn conversion_rejects_keys_argos_equation_cannot_carry() {
    let (key, _) = fixture(51, Fr::from(1u64));

    // `ic[0]` only: no public input at all.
    let mut no_input = key.clone();
    no_input.gamma_abc_g1.truncate(1);
    assert_eq!(
        PreparedVerifierKey::from_groth16_verifying_key(&no_input),
        Err(ArgoAdapterError::UnsupportedPublicInputCount { found: 1 })
    );

    // Two public inputs: Argo multiplies one point by one scalar, so these cannot be represented.
    let mut two_inputs = key.clone();
    two_inputs.gamma_abc_g1.push(G1Affine::generator());
    assert_eq!(
        PreparedVerifierKey::from_groth16_verifying_key(&two_inputs),
        Err(ArgoAdapterError::UnsupportedPublicInputCount { found: 3 })
    );
}

#[test]
fn conversion_rejects_components_that_cannot_constrain_the_equation() {
    let (key, _) = fixture(61, Fr::from(9u64));
    let zero_g1 = G1Affine::zero();
    let zero_g2 = G2Affine::zero();

    let mut zero_ic0 = key.clone();
    zero_ic0.gamma_abc_g1[0] = zero_g1;
    let mut zero_ic1 = key.clone();
    zero_ic1.gamma_abc_g1[1] = zero_g1;

    let cases = [
        Groth16VerifyingKey {
            alpha_g1: zero_g1,
            ..key.clone()
        },
        Groth16VerifyingKey {
            beta_g2: zero_g2,
            ..key.clone()
        },
        Groth16VerifyingKey {
            gamma_g2: zero_g2,
            ..key.clone()
        },
        Groth16VerifyingKey {
            delta_g2: zero_g2,
            ..key.clone()
        },
        zero_ic0,
        zero_ic1,
    ];

    for case in cases {
        assert_eq!(
            PreparedVerifierKey::from_groth16_verifying_key(&case),
            Err(ArgoAdapterError::DegenerateVerifierKey)
        );
    }
}
