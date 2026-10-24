//! Conversion of a standard Groth16 verifying key into Argo's prepared equation.
//!
//! Argo does not verify a Groth16 key. It evaluates the single equation
//!
//! ```text
//! e(A, B) · e(C, H1) · e([x]G1, H2) · c == 1
//! ```
//!
//! over one scalar public input `x`, and reveals a secret whenever that equation fails. A key in
//! `(alpha, beta, gamma, delta, ic)` form therefore has to be projected onto `(G1, H1, H2, c)`:
//!
//! ```text
//! G1 := ic[1]
//! H1 := -delta
//! H2 := -gamma
//! c  := (e(alpha, beta) · e(ic[0], gamma))^-1
//! ```
//!
//! # Why the signs are what they are
//!
//! `ark-groth16` 0.5 accepts a proof when
//! `e(A, B) · e(IC, -gamma) · e(C, -delta) == e(alpha, beta)`, i.e. when the canonical identity
//!
//! ```text
//! e(A, B) == e(alpha, beta) · e(IC(x), gamma) · e(C, delta)
//! ```
//!
//! holds, with `IC(x) = ic[0] + x·ic[1]`. Substituting the mapping above into Argo's left-hand side:
//!
//! ```text
//! e(A, B) · e(C, -delta) · e(x·ic[1], -gamma)
//!   = e(alpha, beta) · e(IC(x), gamma) · e(C, delta) · e(C, delta)^-1 · e(x·ic[1], gamma)^-1
//!   = e(alpha, beta) · e(ic[0], gamma)
//!   = c^-1
//! ```
//!
//! An unnegated `H1`/`H2` would leave a squared `e(C, delta)` and a squared public-input term, so a
//! proof would be rejected for the wrong reason. Pairing signs and order are the part of this
//! conversion that a test has to pin down, not a comment.
//!
//! # What this conversion cannot do
//!
//! Argo carries exactly one public scalar. A key with more than one public input is rejected rather
//! than truncated: dropping inputs would silently unconstrain them. How the manifest maps onto that
//! single scalar (`x = OS2IP_BE(D) mod r` or an equivalent) is a separate, unassessed question and
//! is deliberately not decided here.

use argo::garble::groth16_verifier::VerifierKey;
use ark_bn254::{Bn254, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Field;

use crate::{ArgoAdapterError, PreparedVerifierKey};

/// A standard Groth16 verifying key over BN254, in Arkworks' component form.
///
/// `gamma_abc_g1` holds the constant term followed by one term per public input, exactly as
/// `ark-groth16` stores it. Only `[ic[0], ic[1]]` is representable in Argo's equation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Groth16VerifyingKey {
    /// `[alpha]G1`.
    pub alpha_g1: G1Affine,
    /// `[beta]G2`.
    pub beta_g2: G2Affine,
    /// `[gamma]G2`.
    pub gamma_g2: G2Affine,
    /// `[delta]G2`.
    pub delta_g2: G2Affine,
    /// `ic[0] + sum_i x_i·ic[i]`; exactly two entries are supported.
    pub gamma_abc_g1: Vec<G1Affine>,
}

/// A Groth16 proof and the public scalar it is checked against.
///
/// The field names follow `ark-groth16`'s `Proof` plus the single public input Argo carries, so a
/// caller does not have to invent an ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Groth16Proof {
    /// Proof element `A`.
    pub a: G1Affine,
    /// Proof element `B`.
    pub b: G2Affine,
    /// Proof element `C`.
    pub c: G1Affine,
    /// The single public input, as a scalar in `Fr`.
    ///
    /// [`crate::statement_public_input`] is the proposed derivation from a statement digest.
    pub x: Fr,
}

impl PreparedVerifierKey {
    /// Projects a standard Groth16 verifying key onto Argo's prepared equation.
    ///
    /// The result behaves identically to a key Argo would build itself: a proof accepted by
    /// `ark-groth16` under `key` satisfies the converted equation, and any change to the proof, the
    /// public scalar, or the fixed input term `ic[0]` breaks it.
    pub fn from_groth16_verifying_key(key: &Groth16VerifyingKey) -> Result<Self, ArgoAdapterError> {
        // Argo's equation has room for one scalar, so the key must have exactly one input term.
        if key.gamma_abc_g1.len() != 2 {
            return Err(ArgoAdapterError::UnsupportedPublicInputCount {
                found: key.gamma_abc_g1.len(),
            });
        }

        // Every component appears in the equation. An identity would silently remove a constraint:
        // a zero `gamma`/`delta` makes `C` unchecked, a zero `ic[1]` leaves `x` unchecked, and a
        // zero `ic[0]` drops the fixed term. A real setup has none of these, so fail closed.
        if key.alpha_g1.is_zero()
            || key.beta_g2.is_zero()
            || key.gamma_g2.is_zero()
            || key.delta_g2.is_zero()
            || key.gamma_abc_g1[0].is_zero()
            || key.gamma_abc_g1[1].is_zero()
        {
            return Err(ArgoAdapterError::DegenerateVerifierKey);
        }

        let verifier_key = VerifierKey {
            G1: key.gamma_abc_g1[1],
            H1: (-key.delta_g2.into_group()).into_affine(),
            H2: (-key.gamma_g2.into_group()).into_affine(),
            // The inverse of `e(alpha, beta) · e(ic[0], gamma)`; a valid proof makes
            // `equation_value` return exactly one.
            c: Bn254::multi_pairing(
                [key.alpha_g1, key.gamma_abc_g1[0]],
                [key.beta_g2, key.gamma_g2],
            )
            .0
            .inverse()
            .ok_or(ArgoAdapterError::DegenerateVerifierKey)?,
        };

        Self::from_argo_verifier_key(&verifier_key).ok_or(ArgoAdapterError::VerifierKeyEncoding)
    }

    /// Evaluates Argo's equation `e(A, B) · e(C, H1) · e([x]G1, H2) · c` for `proof`.
    ///
    /// [`Fq12::ONE`] is the accept value. This mirrors the equation Argo's garbled table enforces
    /// and exists so conversion vectors and fixtures can be checked before anything is garbled. It
    /// is not a substitute for a garbled evaluation: the authoritative decision on a real assertion
    /// is Argo's table output, not this function.
    pub fn equation_value(&self, proof: &Groth16Proof) -> Result<Fq12, ArgoAdapterError> {
        let key = self.to_argo_verifier_key()?;
        Ok(Bn254::multi_pairing(
            [proof.a, proof.c, (key.G1 * proof.x).into_affine()],
            [proof.b, key.H1, key.H2],
        )
        .0 * key.c)
    }
}
