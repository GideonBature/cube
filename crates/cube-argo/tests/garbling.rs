//! Tests for setup and evaluation of Argo's garbled Groth16 verifier.
//!
//! One test drives every scenario on purpose: Argo's verifier preprocessing is process-global and
//! this adapter's key guard is too, so two tests that garbled different keys would interfere with
//! each other instead of testing anything.
//!
//! This is the slow test in the crate — roughly two minutes in a debug build, most of it in table
//! evaluation rather than garbling. The printed setup duration and serialized size are recorded
//! measurements, not assertions: they are the deployment numbers this table actually has on this
//! machine.

mod common;

use ark_bn254::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};
use cube_argo::{
    reset_verifier_key_identity, statement_public_input, ArgoAdapterError, GarbledVerifier,
    GarblingConfig, PreparedVerifierKey, VerifierOutcome, RECOMMENDED_SETUP_STACK_BYTES,
};

/// A non-zero disclosure secret.
const SECRET: [u8; 32] = [0x5a; 32];

/// The statement digest the accepted proof is checked against.
const DIGEST: [u8; 32] = [0x11; 32];

/// A different statement digest, which must not be accepted by the same proof.
const OTHER_DIGEST: [u8; 32] = [0x12; 32];

#[test]
fn garbled_verifier_accepts_valid_proofs_and_discloses_on_failure() {
    // Setup overflows the default test-thread stack, so it runs on a thread with the documented
    // size. This mirrors how a caller has to run it.
    std::thread::Builder::new()
        .name("cube-argo-garbling".to_string())
        .stack_size(RECOMMENDED_SETUP_STACK_BYTES)
        .spawn(garbling_scenarios)
        .expect("spawn garbling thread")
        .join()
        .expect("the garbling scenarios must not panic");
}

fn garbling_scenarios() {
    // Start from a clean process-wide verifier-key identity.
    reset_verifier_key_identity();

    let x = statement_public_input(DIGEST);
    assert_ne!(x, statement_public_input(OTHER_DIGEST));
    let (key, proof) = common::fixture(101, x);
    let prepared = PreparedVerifierKey::from_groth16_verifying_key(&key).expect("convert");

    let config = GarblingConfig {
        rng_seed: 0x0123_4567_89ab_cdef,
        disclosure_secret: SECRET.to_vec(),
    };

    // 1 Unusable setup parameters are refused before any table exists.
    assert!(matches!(
        GarbledVerifier::setup(
            &GarblingConfig {
                rng_seed: 0,
                disclosure_secret: SECRET.to_vec(),
            },
            &prepared,
            [0x11; 16],
        ),
        Err(ArgoAdapterError::ZeroRngSeed)
    ));
    assert!(matches!(
        GarbledVerifier::setup(
            &GarblingConfig {
                rng_seed: 1,
                disclosure_secret: vec![0u8; 32],
            },
            &prepared,
            [0x11; 16],
        ),
        Err(ArgoAdapterError::ZeroDisclosureSecret)
    ));

    // 2 A valid setup succeeds and is bound to the key and the instance identifier.
    let setup_started = std::time::Instant::now();
    let verifier = GarbledVerifier::setup(&config, &prepared, [0x11; 16]).expect("setup");
    println!("setup took: {:?}", setup_started.elapsed());
    assert_eq!(verifier.instance_id(), [0x11; 16]);
    assert_eq!(verifier.key_identity(), prepared.identity());

    // 3 A proof the canonical identity accepts discloses nothing.
    assert!(common::canonical_identity_holds(&key, &proof));
    assert_eq!(
        verifier.evaluate(&proof).expect("evaluate"),
        VerifierOutcome::Accepted
    );

    // 4 A different statement digest projects to a different scalar, breaks the equation and
    //   discloses the configured secret.
    let mut wrong_x = proof;
    wrong_x.x = statement_public_input(OTHER_DIGEST);
    assert!(!common::canonical_identity_holds(&key, &wrong_x));
    assert_eq!(
        verifier.evaluate(&wrong_x).expect("evaluate"),
        VerifierOutcome::Disclosed
    );

    // 5 A tampered proof element does the same. This is the case the garbled table exists for.
    let mut moved_c = proof;
    moved_c.c = (moved_c.c.into_group() + G1Affine::generator()).into_affine();
    assert_eq!(
        verifier.evaluate(&moved_c).expect("evaluate"),
        VerifierOutcome::Disclosed
    );

    // 6 The table is measurable, which is the artifact deployment sizing needs.
    let table_bytes = verifier.serialized_size().expect("serialized size");
    println!("serialized table size: {table_bytes} bytes");
    assert!(table_bytes > 0, "a garbled table cannot be empty");

    // 7 A second, different verifier key is refused in the same process. Upstream would silently
    //   reuse the first key's precomputation, so this refusal is the guard, not an inconvenience.
    let (other_key, _) = common::fixture(102, x);
    let other_prepared =
        PreparedVerifierKey::from_groth16_verifying_key(&other_key).expect("convert");
    assert!(matches!(
        GarbledVerifier::setup(&config, &other_prepared, [0x22; 16]),
        Err(ArgoAdapterError::ConflictingVerifierKey { .. })
    ));
}
