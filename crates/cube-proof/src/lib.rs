//! Groth16 relations for Cube v1.
//!
//! This crate owns the circuit side of the proof statement: it takes the canonical manifest bytes
//! and the values a transition must satisfy, and turns them into constraints over BN254. It
//! deliberately contains no proving, no setup and no chain access yet.
//!
//! # What exists
//!
//! `fund_split`: the `FundSplit` statement binding. It recomputes the tagged SHA-256 statement
//! digest in-circuit from the 665 manifest bytes and constrains the 70/30 split and the remainder
//! range from the payout amounts the manifest itself commits to.
//!
//! # What does not exist
//!
//! - **No prover or verifying key.** The crate produces a constraint system that a test can check
//!   for satisfaction. Generating a Groth16 key and proof is the next step, and it is what makes the
//!   output usable by Argo.
//! - **No state-transition validity.** Balances, caller sequences, replay protection and the
//!   contract's own arithmetic are not constrained yet; only what the manifest commits to is.
//! - **No authorization.** The caller signature is not checked in-circuit. BIP-340 over BN254 is a
//!   separate gadget and a gate item of its own; nothing here pretends otherwise.
//! - **No chain binding.** The public scalar is assumed to have been read from an authenticated
//!   Bitcoin output; this crate never looks at a chain.
//!
//! # Why the digest is recomputed rather than supplied
//!
//! If the circuit accepted the digest as a witness and compared it to the public scalar, any
//! witness could be paired with any statement: the arithmetic would be unconstrained relative to
//! the manifest. Hashing the manifest bytes in-circuit is what ties the split to the statement the
//! Bitcoin output commits to.

pub mod fund_split;

pub use fund_split::{
    statement_scalar, tagged_statement_digest, FundSplitCircuit, MANIFEST_ENCODED_LEN,
    PAYOUTS_OFFSET, PAYOUT_ENCODED_LEN, STATEMENT_TAG,
};
