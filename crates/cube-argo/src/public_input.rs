//! Derivation of Argo's single public scalar from a statement digest.
//!
//! Argo's equation multiplies one `G1` point by one scalar, so a 32-byte statement digest has to be
//! projected onto a scalar field element. This module owns that projection and states exactly what
//! it does and does not guarantee.
//!
//! # The proposal
//!
//! ```text
//! x = OS2IP_BE(D) mod r
//! ```
//!
//! `D` is the 32-byte statement digest interpreted as a big-endian unsigned integer, `r` is the
//! BN254 scalar-field modulus, and `x` is Argo's public scalar. Byte order is fixed: the digest's
//! first byte is the most significant. Reversing it produces a different scalar and therefore a
//! different statement.
//!
//! # What this costs
//!
//! `r ≈ 2^253.99`, so the map from 256-bit digests onto scalars is not injective: on average about
//! four digests share one scalar, and a collision is easy to construct (`D` and `D + r` agree
//! whenever both fit in 32 bytes, which holds for every `D < 2^256 - r`). Tests demonstrate the
//! smallest instance: the all-zero digest and the modulus itself both map to zero.
//!
//! Consequences that must not be papered over:
//!
//! - The scalar alone **does not bind** a manifest. Two different statements can produce the same
//!   `x`, so a prover for one would satisfy the other's public input.
//! - Binding therefore has to come from elsewhere: the relation must constrain the digest (for
//!   example by hashing the statement preimage inside the circuit), and the Bitcoin-side claim
//!   output's committed digest remains the authoritative on-chain binding.
//! - CRYPTO-01 stays open. This mapping is a tested proposal for byte order and range handling, not
//!   an assessed construction.
//!
//! # Why it lives in the adapter
//!
//! The manifest stays a pure commitment: `TransitionManifest::statement_digest` deliberately does not
//! know how a proof consumes it. Changing the adapter's mapping must not silently change the
//! manifest, and keeping them separate makes that impossible by construction. If a multi-input
//! verifier replaces the single scalar, this module and its tests change with it.

use ark_bn254::Fr;
use ark_ff::PrimeField;

/// Projects a 32-byte statement digest onto Argo's single public scalar.
///
/// Big-endian OS2IP, then reduction modulo the BN254 scalar-field modulus. See the module
/// documentation for what the reduction loses and why this is a proposal rather than a settled
/// binding.
pub fn statement_public_input(digest: [u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(&digest)
}
