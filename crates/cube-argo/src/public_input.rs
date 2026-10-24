//! Projection of a statement digest onto Argo's single public scalar.
//!
//! Argo's equation multiplies one `G1` point by one scalar, so a 32-byte statement digest has to
//! become one scalar field element. This module owns that projection and refuses anything that would
//! make it lossy.
//!
//! # The rule
//!
//! ```text
//! x = OS2IP_BE(D),  accepted only when D < r
//! ```
//!
//! `D` is the statement digest as a big-endian integer and `r` is the BN254 scalar-field modulus.
//! The digest is field-sized by construction: `CubeV1/Statement/v1` clears the top three bits, so
//! every honest digest is below `2^253 < r`. Because the projection never reduces, it is injective on
//! the accepted set: one scalar identifies exactly one statement.
//!
//! # What went wrong with the obvious alternative
//!
//! The earlier proposal reduced modulo `r`. That is lossy: about four 256-bit digests share each
//! scalar, so a prover could satisfy the same public input with a different statement, and the
//! scalar would bind nothing. The alternative of grinding the digest below `r` needs a free nonce
//! field that the manifest encoding does not have. Truncating at the source is the only option that
//! keeps the mapping injective without changing the manifest schema.
//!
//! # Consequences
//!
//! - The mapping is **not** a compression of 256 bits into a smaller field: three bits of hash
//!   output are dropped when the statement is defined. Collision resistance stays above 126 bits.
//! - A digest at or above `r` is refused instead of reduced. Accepting it would silently reintroduce
//!   the collision, so the failure is loud.
//! - The truncation lives in the statement, not here. A verifier recomputes `D` with the same rule
//!   (`TransitionManifest::statement_digest`) and then projects it; this module never guesses.
//!
//! # Why it lives in the adapter
//!
//! The manifest stays a pure commitment: it does not know how a proof consumes the digest. Keeping
//! the projection here means changing the proof interface cannot silently change a committed value.
//! If a multi-input verifier replaces the single scalar, this module and its tests change with it.

use crate::ArgoAdapterError;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Projects a field-sized statement digest onto Argo's single public scalar.
///
/// Big-endian OS2IP with no reduction. Returns [`ArgoAdapterError::StatementDigestNotBelowModulus`]
/// when the digest is at or above the scalar modulus, because reducing it would be lossy.
pub fn statement_public_input(digest: [u8; 32]) -> Result<Fr, ArgoAdapterError> {
    let scalar = Fr::from_be_bytes_mod_order(&digest);

    // A digest below the modulus survives the conversion unchanged. Re-encoding is the check: if the
    // canonical bytes differ, the conversion reduced, and the projection is not injective for this
    // input.
    let canonical = scalar.into_bigint().to_bytes_be();
    let mut expected = [0u8; 32];
    if canonical.len() > 32 {
        return Err(ArgoAdapterError::StatementDigestNotBelowModulus { digest });
    }
    expected[32 - canonical.len()..].copy_from_slice(&canonical);

    if expected != digest {
        return Err(ArgoAdapterError::StatementDigestNotBelowModulus { digest });
    }

    Ok(scalar)
}
