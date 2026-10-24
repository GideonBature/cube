//! Tests for setup and evaluation of Argo's garbled Groth16 verifier.
//!
//! One test drives every scenario on purpose: it garbles two different verifier keys in a single
//! process, which is the regression that `vendor/argo/PATCHES.md` item 1 exists for. With upstream's
//! unkeyed preprocessing cache the second table is garbled from the first key's pairing powers and
//! therefore rejects its own valid proof.
//!
//! This is the slow test in the crate — a few minutes in a debug build, mostly table evaluation
//! rather than garbling. The printed setup duration and serialized size are recorded measurements,
//! not assertions: they are the numbers this table actually has on this machine.

mod common;

use cube_argo::{
    disclosure_secret_commitment, statement_public_input, ArgoAdapterError, AuthenticatedInput,
    GarbledVerifier, GarblingConfig, PreparedVerifierKey, VerifierOutcome,
    RECOMMENDED_SETUP_STACK_BYTES,
};

/// A non-zero disclosure secret.
const SECRET: [u8; 32] = [0x5a; 32];

/// The statement digest the first proof is checked against.
const DIGEST: [u8; 32] = [0x11; 32];

/// A different statement digest, which must not be accepted by the same proof.
const OTHER_DIGEST: [u8; 32] = [0x12; 32];

#[test]
fn garbled_verifiers_are_bound_to_their_own_keys() {
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
    let x = statement_public_input(DIGEST).expect("the digest must be field-sized");
    assert_ne!(
        x,
        statement_public_input(OTHER_DIGEST).expect("the digest must be field-sized")
    );

    let (raw_key_a, proof_a) = common::fixture(101, x);
    let prepared_a = PreparedVerifierKey::from_groth16_verifying_key(&raw_key_a).expect("convert");

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
            &prepared_a,
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
            &prepared_a,
            [0x11; 16],
        ),
        Err(ArgoAdapterError::ZeroDisclosureSecret)
    ));

    // 2 The first key garbles and is bound to its own identity and instance identifier.
    let setup_started = std::time::Instant::now();
    let verifier_a = GarbledVerifier::setup(&config, &prepared_a, [0x11; 16]).expect("setup A");
    println!("setup A took: {:?}", setup_started.elapsed());
    assert_eq!(verifier_a.instance_id(), [0x11; 16]);
    assert_eq!(verifier_a.key_identity(), prepared_a.identity());

    // 3 A proof the canonical identity accepts discloses nothing.
    assert!(common::canonical_identity_holds(&raw_key_a, &proof_a));
    assert_eq!(
        verifier_a.evaluate(&proof_a).expect("evaluate"),
        VerifierOutcome::Accepted
    );

    // 4 A different statement digest projects to a different scalar, breaks the equation and
    //   discloses the configured secret.
    let mut wrong_digest = proof_a;
    wrong_digest.x = statement_public_input(OTHER_DIGEST).expect("the digest must be field-sized");
    assert!(!common::canonical_identity_holds(&raw_key_a, &wrong_digest));
    assert_eq!(
        verifier_a.evaluate(&wrong_digest).expect("evaluate"),
        VerifierOutcome::Disclosed
    );

    // 4a The published input reproduces the honest verdict without the input MAC key. This is the
    //    property an on-chain assertion needs: the challenger has the table and the bytes, not the
    //    key.
    let published = verifier_a.authenticate(&proof_a).expect("authenticate");
    assert_eq!(published.public_input().expect("public input"), x);
    assert_eq!(
        published.as_bytes().len(),
        36_928,
        "the published input and MAC have a fixed measured size"
    );
    assert_eq!(
        verifier_a
            .evaluate_authenticated(&published)
            .expect("evaluate published"),
        VerifierOutcome::Accepted
    );
    assert_eq!(
        AuthenticatedInput::from_bytes(published.as_bytes()).expect("canonical bytes"),
        published
    );

    // 4b The same bytes with a different statement disclose the secret: the MAC authenticates the
    //    input it was made for, not just any input.
    let other_published = verifier_a
        .authenticate(&wrong_digest)
        .expect("authenticate");
    assert_eq!(
        verifier_a
            .evaluate_authenticated(&other_published)
            .expect("evaluate other"),
        VerifierOutcome::Disclosed
    );
    assert_ne!(published.digest(), other_published.digest());

    // 4c Attaching the wrong MAC to the honest input does not disclose the secret: Argo's
    //    sub-tables reject a MAC that does not decode before the conditional reveal runs. That is a
    //    liveness result, not evidence, and it is why the binding design also requires the setup
    //    holder's signature over the published bytes (`docs/bind_01.md`). The test records the
    //    actual behaviour instead of assuming the reveal.
    let honest = published.to_bytes();
    let other = other_published.to_bytes();
    let input_len = u32::from_le_bytes([honest[0], honest[1], honest[2], honest[3]]) as usize;
    let mut spliced = honest[..4 + input_len].to_vec();
    spliced.extend_from_slice(&other[4 + input_len..]);
    let spliced = AuthenticatedInput::from_bytes(&spliced).expect("canonical splice");
    assert!(matches!(
        verifier_a.evaluate_authenticated(&spliced),
        Err(ArgoAdapterError::EvaluationFailed)
    ));

    // 4d Trailing bytes are refused instead of being folded into the digest.
    let mut extended = published.to_bytes();
    extended.push(0x00);
    assert!(matches!(
        AuthenticatedInput::from_bytes(&extended),
        Err(ArgoAdapterError::InvalidAuthenticatedInput)
    ));

    // 5 A second, different key garbles in the same process. Under upstream's unkeyed cache this
    //   table would be built from the first key's powers and would reject `proof_b` below.
    let (raw_key_b, proof_b) = common::fixture(102, x);
    let prepared_b = PreparedVerifierKey::from_groth16_verifying_key(&raw_key_b).expect("convert");
    assert_ne!(prepared_b.identity(), prepared_a.identity());

    let verifier_b = GarbledVerifier::setup(&config, &prepared_b, [0x22; 16]).expect("setup B");

    // 6 Each table accepts the proof made for its own key.
    assert_eq!(
        verifier_b.evaluate(&proof_b).expect("evaluate"),
        VerifierOutcome::Accepted
    );

    // 7 A table does not accept a proof made for another key.
    assert_eq!(
        verifier_b.evaluate(&proof_a).expect("evaluate"),
        VerifierOutcome::Disclosed
    );

    // 8 The table is measurable, which is the artifact deployment sizing needs.
    let table_bytes = verifier_a.serialized_size().expect("serialized size");
    println!("serialized table size: {table_bytes} bytes");
    assert!(table_bytes > 0, "a garbled table cannot be empty");

    // 9 The two commitments an assertion publishes are present, distinct and instance-bound.
    assert_ne!(verifier_a.table_digest(), [0u8; 32]);
    assert_ne!(verifier_a.disclosure_secret_commitment(), [0u8; 32]);
    // The commitment is over the secret alone; the instance binding is in the assertion digest B.
    assert_eq!(
        verifier_a.disclosure_secret_commitment(),
        verifier_b.disclosure_secret_commitment()
    );
    assert_ne!(verifier_a.table_digest(), verifier_b.table_digest());

    // 10 The disclosure commitment equals the main crate's golden vector for the same instance and
    //    secret, so the chain-side check and the adapter cannot drift.
    let commitment = disclosure_secret_commitment(&[0x11; 32]).expect("a canonical secret");
    assert_eq!(
        commitment,
        [
            0x02, 0xd4, 0x49, 0xa3, 0x1f, 0xbb, 0x26, 0x7c, 0x8f, 0x35, 0x2e, 0x99, 0x68, 0xa7,
            0x9e, 0x3e, 0x5f, 0xc9, 0x5c, 0x1b, 0xbe, 0xaa, 0x50, 0x2f, 0xd6, 0x45, 0x4e, 0xbd,
            0xe5, 0xa4, 0xbe, 0xdc,
        ]
    );
    assert!(
        disclosure_secret_commitment(&[0xff; 32]).is_none(),
        "a non-canonical field encoding must not be committed"
    );
}
