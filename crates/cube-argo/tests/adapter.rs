//! Tests for the Argo adapter.
//!
//! These do not garble anything. They cover the boundary this crate owns: configuration validation,
//! the process-wide verifier-key guard that works around upstream's unkeyed preprocessing cache, and
//! the canonical byte carrier that crosses the arkworks 0.4 / 0.5 gap.
//!
//! Garbling itself has no test here because it needs a Groth16 verifying key from a real relation,
//! and no relation exists yet. That dependency is deliberate and is recorded in `lib.rs`.

use ark_bn254::{Fq12, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use cube_argo::{
    prepare_verifier_key, register_verifier_key_identity, registered_verifier_key_identity,
    reset_verifier_key_identity, ArgoAdapterError, GarblingConfig, PreparedVerifierKey,
};

/// A non-zero disclosure secret.
const SECRET_BYTES: [u8; 32] = [0x11; 32];

#[test]
fn garbling_config_rejects_unusable_entropy_and_secrets() {
    // 1 A zero seed makes the garbling reproducible by anyone.
    assert_eq!(
        GarblingConfig {
            rng_seed: 0,
            disclosure_secret: SECRET_BYTES.to_vec(),
        }
        .validate(),
        Err(ArgoAdapterError::ZeroRngSeed)
    );

    // 2 An all-zero secret is Argo's own "no disclosure" sentinel.
    assert_eq!(
        GarblingConfig {
            rng_seed: 1,
            disclosure_secret: vec![0u8; 32],
        }
        .validate(),
        Err(ArgoAdapterError::ZeroDisclosureSecret)
    );

    // 3 An empty secret also decodes to zero.
    assert_eq!(
        GarblingConfig {
            rng_seed: 1,
            disclosure_secret: Vec::new(),
        }
        .validate(),
        Err(ArgoAdapterError::ZeroDisclosureSecret)
    );

    // 4 A non-zero byte string can still reduce to zero. The base-field modulus itself, encoded
    //   little-endian, is the case that a byte-level "is it all zero" check would miss.
    let modulus_le = <ark_bn254::Fq as PrimeField>::MODULUS.to_bytes_le();
    assert!(
        modulus_le.iter().any(|byte| *byte != 0),
        "the modulus must be a non-zero byte string for this test to mean anything"
    );
    assert_eq!(
        GarblingConfig {
            rng_seed: 1,
            disclosure_secret: modulus_le,
        }
        .validate(),
        Err(ArgoAdapterError::ZeroDisclosureSecret)
    );

    // 5 A usable configuration passes and yields a non-zero field element.
    let config = GarblingConfig {
        rng_seed: 0xfeed_face_dead_beef,
        disclosure_secret: SECRET_BYTES.to_vec(),
    };
    config.validate().expect("must be valid");
    assert_ne!(
        config.disclosure_secret_field().expect("field element"),
        ark_bn254::Fq::from(0u64)
    );
}

#[test]
fn verifier_key_identity_guard_allows_one_key_per_process() {
    reset_verifier_key_identity();
    assert_eq!(registered_verifier_key_identity(), None);

    let first = [0x01u8; 32];
    let second = [0x02u8; 32];

    // 1 The first identity registers.
    assert_eq!(register_verifier_key_identity(first), Ok(()));
    assert_eq!(registered_verifier_key_identity(), Some(first));

    // 2 Re-registering the same identity is idempotent, so a retry cannot fail spuriously.
    assert_eq!(register_verifier_key_identity(first), Ok(()));

    // 3 A different identity is refused, naming both sides. Upstream would otherwise reuse the
    //   first key's precomputation for the second key.
    assert_eq!(
        register_verifier_key_identity(second),
        Err(ArgoAdapterError::ConflictingVerifierKey {
            registered: first,
            rejected: second,
        })
    );
    assert_eq!(
        registered_verifier_key_identity(),
        Some(first),
        "a refused registration must not change the registered identity"
    );

    reset_verifier_key_identity();
}

#[test]
fn prepared_verifier_key_round_trips_through_canonical_bytes() {
    // 1 Build a synthetic prepared key. The points are random, so this proves the byte carrier, not
    //   a Groth16 relation.
    let mut rng = StdRng::seed_from_u64(7);
    let verifier_key = prepare_verifier_key(
        G1Affine::rand(&mut rng),
        G2Affine::rand(&mut rng),
        G2Affine::rand(&mut rng),
        Fq12::rand(&mut rng),
    );

    let prepared =
        PreparedVerifierKey::from_argo_verifier_key(&verifier_key).expect("the key must serialize");
    assert!(
        !prepared.canonical_bytes.is_empty(),
        "the carrier must not be empty"
    );

    // 2 The bytes decode back into Argo's own type.
    let decoded = prepared
        .to_argo_verifier_key()
        .expect("the bytes must decode");

    // 3 `VerifierKey` has no `PartialEq`, so compare by re-encoding: a stable round trip.
    let reencoded = PreparedVerifierKey::from_argo_verifier_key(&decoded).expect("re-encode");
    assert_eq!(reencoded.canonical_bytes, prepared.canonical_bytes);
    assert_eq!(reencoded.identity(), prepared.identity());

    // 4 The identity is a function of the key: a different key has a different identity.
    let other = prepare_verifier_key(
        G1Affine::rand(&mut rng),
        G2Affine::rand(&mut rng),
        G2Affine::rand(&mut rng),
        Fq12::rand(&mut rng),
    );
    let other_prepared = PreparedVerifierKey::from_argo_verifier_key(&other).expect("serialize");
    assert_ne!(other_prepared.identity(), prepared.identity());

    // 5 Garbage bytes are refused rather than decoded into a bogus key.
    // `matches!` rather than `assert_eq!` because `VerifierKey` is not `PartialEq`.
    assert!(matches!(
        PreparedVerifierKey::from_canonical_bytes(vec![0xff; 8]).to_argo_verifier_key(),
        Err(ArgoAdapterError::InvalidVerifierKeyBytes)
    ));
}
