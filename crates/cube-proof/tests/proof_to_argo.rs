//! End-to-end: a real Groth16 proof of the `FundSplit` statement is accepted by Argo's garbled
//! verifier, and a tampered proof discloses the secret.
//!
//! This is the first chain where all the pieces meet: the circuit binds the manifest, Groth16
//! produces a proof, the adapter converts the verifying key into Argo's equation, and the table
//! decides. It is `#[ignore]`d because setup, proving and garbling are slow in a debug build:
//!
//! ```text
//! cargo test -p cube-proof --release --test proof_to_argo -- --ignored --nocapture
//! ```
//!
//! Measured in release on an aarch64 laptop: setup 6.7 s, prove 4.3 s, garble 0.8 s, whole test
//! 14.4 s. Debug multiplies the cryptographic work by a large factor, so the test stays opt-in.
//!
//! The setup is a single-party **trusted test setup**: this test proves the integration, not a
//! deployment.

mod common;

use ark_bn254::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use cube_argo::{
    GarbledVerifier, GarblingConfig, Groth16VerifyingKey, PreparedVerifierKey, VerifierOutcome,
    RECOMMENDED_SETUP_STACK_BYTES,
};
use cube_proof::fund_split::FundSplitCircuit;
use cube_proof::groth16::{prove, setup, verify};

#[test]
#[ignore = "Groth16 setup/proving and garbling are minutes; run in release with --ignored"]
fn a_real_proof_is_accepted_by_argo_and_a_tampered_proof_discloses() {
    // Garbling overflows the default thread stack, so the whole scenario runs on a sized thread.
    std::thread::Builder::new()
        .name("cube-proof-e2e".to_string())
        .stack_size(RECOMMENDED_SETUP_STACK_BYTES)
        .spawn(scenario)
        .expect("spawn")
        .join()
        .expect("the scenario must not panic");
}

fn scenario() {
    let fixture = common::fixture();
    let circuit = FundSplitCircuit::from_parts(
        fixture.manifest_bytes(),
        fixture.previous_state,
        fixture.resulting_state,
        0,
    );
    let statement = circuit.statement;

    // 1 A deterministic seed is acceptable for a fixture and unacceptable for a deployment.
    let mut rng = StdRng::seed_from_u64(0xc0ff_ee00_1234_5678);

    let started = std::time::Instant::now();
    let proving_key = setup(circuit.clone(), &mut rng).expect("setup");
    println!("groth16 setup: {:?}", started.elapsed());

    let started = std::time::Instant::now();
    let proof = prove(circuit, &proving_key, &mut rng).expect("prove");
    println!("groth16 prove: {:?}", started.elapsed());

    // 2 Ordinary Groth16 accepts the proof for this statement and rejects another one.
    assert!(
        verify(&proving_key.vk, statement, &proof).expect("verify"),
        "the honest proof must verify"
    );
    assert!(
        !verify(&proving_key.vk, statement + Fr::from(1u64), &proof).expect("verify"),
        "a different statement must not verify"
    );

    // 3 Convert the verifying key into Argo's equation. The key has exactly one public input.
    assert_eq!(proving_key.vk.gamma_abc_g1.len(), 2);
    let verifier_key = Groth16VerifyingKey {
        alpha_g1: proving_key.vk.alpha_g1,
        beta_g2: proving_key.vk.beta_g2,
        gamma_g2: proving_key.vk.gamma_g2,
        delta_g2: proving_key.vk.delta_g2,
        gamma_abc_g1: proving_key.vk.gamma_abc_g1.clone(),
    };
    let prepared = PreparedVerifierKey::from_groth16_verifying_key(&verifier_key)
        .expect("the verifying key must convert");

    // 4 Garble the table and evaluate the real proof.
    let config = GarblingConfig {
        rng_seed: 0x5eed_5eed_5eed_5eed,
        disclosure_secret: vec![0x5a; 32],
    };
    let started = std::time::Instant::now();
    let verifier = GarbledVerifier::setup(&config, &prepared, [0x11; 16]).expect("garble");
    println!("garble: {:?}", started.elapsed());

    let honest = cube_argo::Groth16Proof {
        a: proof.a,
        b: proof.b,
        c: proof.c,
        x: statement,
    };
    assert_eq!(
        verifier.evaluate(&honest).expect("evaluate"),
        VerifierOutcome::Accepted
    );

    // 5 A tampered proof must disclose the secret rather than pass.
    let tampered = cube_argo::Groth16Proof {
        a: (proof.a.into_group() + G1Affine::generator()).into_affine(),
        ..honest
    };
    assert_eq!(
        verifier.evaluate(&tampered).expect("evaluate"),
        VerifierOutcome::Disclosed
    );

    // 6 The proof for another statement is rejected by the table as well.
    let other_statement = cube_argo::Groth16Proof {
        x: statement + Fr::from(1u64),
        ..honest
    };
    assert_eq!(
        verifier.evaluate(&other_statement).expect("evaluate"),
        VerifierOutcome::Disclosed
    );

    println!(
        "serialized table size: {} bytes",
        verifier.serialized_size().expect("size")
    );
}
