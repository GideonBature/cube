//! Shared algebraic fixtures for the adapter tests.
//!
//! Every point is a known scalar multiple of the generator, so the canonical Groth16 identity
//! reduces to a scalar equation that `c` is solved for. That makes acceptance and rejection exact
//! and lets the pairing signs be checked without a prover. A fixture that satisfies the identity is
//! still **not** an execution proof for any relation; it says nothing about a circuit.

#![allow(dead_code)]

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use cube_argo::{Groth16Proof, Groth16VerifyingKey};

/// Builds a key and proof satisfying
/// `e(A, B) == e(alpha, beta) · e(IC(x), gamma) · e(C, delta)`.
///
/// With `G`/`H` the generators the identity becomes
/// `a·b == alpha·beta + (ic0 + x·ic1)·gamma + c·delta`, which `c` is solved for.
pub fn fixture(seed: u64, x: Fr) -> (Groth16VerifyingKey, Groth16Proof) {
    let mut rng = StdRng::seed_from_u64(seed);
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();

    let alpha = Fr::rand(&mut rng);
    let beta = Fr::rand(&mut rng);
    let gamma = Fr::rand(&mut rng);
    let delta = Fr::rand(&mut rng);
    let ic0 = Fr::rand(&mut rng);
    let ic1 = Fr::rand(&mut rng);
    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);

    let c = (a * b - alpha * beta - (ic0 + x * ic1) * gamma) / delta;

    let key = Groth16VerifyingKey {
        alpha_g1: (g1 * alpha).into_affine(),
        beta_g2: (g2 * beta).into_affine(),
        gamma_g2: (g2 * gamma).into_affine(),
        delta_g2: (g2 * delta).into_affine(),
        gamma_abc_g1: vec![(g1 * ic0).into_affine(), (g1 * ic1).into_affine()],
    };

    let proof = Groth16Proof {
        a: (g1 * a).into_affine(),
        b: (g2 * b).into_affine(),
        c: (g1 * c).into_affine(),
        x,
    };

    (key, proof)
}

/// `IC(x) = ic[0] + x·ic[1]`.
pub fn input_commitment(key: &Groth16VerifyingKey, x: Fr) -> G1Affine {
    (key.gamma_abc_g1[0].into_group() + key.gamma_abc_g1[1] * x).into_affine()
}

/// The canonical Groth16 identity, evaluated without Argo's equation:
/// `e(A, B) == e(alpha, beta) · e(IC(x), gamma) · e(C, delta)`.
pub fn canonical_identity_holds(key: &Groth16VerifyingKey, proof: &Groth16Proof) -> bool {
    let lhs = Bn254::pairing(proof.a, proof.b).0;
    let rhs = Bn254::multi_pairing(
        [key.alpha_g1, input_commitment(key, proof.x), proof.c],
        [key.beta_g2, key.gamma_g2, key.delta_g2],
    )
    .0;
    lhs == rhs
}
