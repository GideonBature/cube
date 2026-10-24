//! Groth16 setup, proving and verification for the `FundSplit` relation.
//!
//! This module is the bridge between the constraint system and a verifier. It exposes the three
//! operations a prover and a verifier need, with no policy attached:
//!
//! - [`setup`] creates a proving key from a circuit instance. The randomness is the caller's; a
//!   deterministic seed is only acceptable for test fixtures, never for a deployment.
//! - [`prove`] produces a proof for one circuit instance.
//! - [`verify`] checks a proof against the single public scalar.
//!
//! # What this is not
//!
//! - **Not a trusted setup.** A single-party setup is a test key: whoever ran it knows the toxic
//!   waste and could forge proofs. The specification's participant-scoped setup procedure is
//!   separate work, so a key produced here is labelled trusted test setup.
//! - **Not a deployment path.** The verifying key still has to be converted into Argo's equation
//!   and garbled; that lives in `cube-argo` and is exercised by the integration test.
//! - **Not recursive, aggregated or batched.** One statement, one proof.

use crate::fund_split::FundSplitCircuit;
use ark_bn254::Bn254;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_std::rand::Rng;
use ark_relations::r1cs::SynthesisError;

/// The proving key type of the `FundSplit` relation.
pub type FundSplitProvingKey = ProvingKey<Bn254>;

/// The verifying key type of the `FundSplit` relation.
pub type FundSplitVerifyingKey = VerifyingKey<Bn254>;

/// The proof type of the `FundSplit` relation.
pub type FundSplitProof = Proof<Bn254>;

/// Runs a single-party Groth16 setup for `circuit`.
///
/// The resulting key is a **trusted test setup**: the caller holds the trapdoor. Use it for
/// fixtures and regtest evidence only.
pub fn setup(
    circuit: FundSplitCircuit,
    rng: &mut impl Rng,
) -> Result<FundSplitProvingKey, SynthesisError> {
    Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, rng)
}

/// Produces a proof for `circuit` under `proving_key`.
pub fn prove(
    circuit: FundSplitCircuit,
    proving_key: &FundSplitProvingKey,
    rng: &mut impl Rng,
) -> Result<FundSplitProof, SynthesisError> {
    Groth16::<Bn254>::create_random_proof_with_reduction(circuit, proving_key, rng)
}

/// Verifies `proof` for the single public scalar `statement`.
pub fn verify(
    verifying_key: &FundSplitVerifyingKey,
    statement: ark_bn254::Fr,
    proof: &FundSplitProof,
) -> Result<bool, SynthesisError> {
    let prepared = ark_groth16::prepare_verifying_key(verifying_key);
    Groth16::<Bn254>::verify_proof(&prepared, proof, &[statement])
}
