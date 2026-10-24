//! Groth16 relations for Cube v1.
//!
//! This crate owns the circuit side of the proof statement: it takes the canonical manifest bytes
//! and the values a transition must satisfy, and turns them into constraints over BN254. It
//! deliberately contains no proving, no setup and no chain access yet.
//!
//! # What exists
//!
//! - `fund_split`: the `FundSplit` relation. It recomputes the tagged statement digest in-circuit
//!   from the 629 manifest bytes, binds both 343-byte state preimages to the digests the manifest
//!   commits, and enforces the funding transition: phase, instance identity, balances, shadows,
//!   sequences and the 70/30 split.
//! - `groth16`: setup, proving and verification for that relation. A key produced here is a
//!   single-party **trusted test setup**, not a deployment.
//!
//! # What does not exist
//!
//! - **No trusted or participant-scoped setup.** Whoever runs [`groth16::setup`] holds the trapdoor.
//! - **No replay protection in-circuit.** The consumed-operation set is unbounded and is not
//!   committed by the state digest, so the relation cannot show an operation id was unused.
//! - **No authorization.** The caller signature is not checked in-circuit. BIP-340 over BN254 is a
//!   separate gadget and a gate item of its own; nothing here pretends otherwise.
//! - **No chain binding.** The public scalar is assumed to have been read from an authenticated
//!   Bitcoin output; this crate never looks at a chain.
//! - **No Argo integration in-crate.** The verifying key is converted and garbled by `cube-argo`;
//!   the integration test in `tests/proof_to_argo.rs` is what exercises that path.
//!
//! # Why the digest is recomputed rather than supplied
//!
//! If the circuit accepted the digest as a witness and compared it to the public scalar, any
//! witness could be paired with any statement: the arithmetic would be unconstrained relative to
//! the manifest. Hashing the manifest bytes in-circuit is what ties the split to the statement the
//! Bitcoin output commits to.

pub mod fund_split;
pub mod groth16;

pub use fund_split::{
    statement_scalar, tagged_state_digest, tagged_statement_digest, FundSplitCircuit,
    MANIFEST_ENCODED_LEN, PAYOUTS_OFFSET, PAYOUT_ENCODED_LEN, STATEMENT_TAG, STATE_ENCODED_LEN,
};
