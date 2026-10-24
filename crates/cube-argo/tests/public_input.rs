//! Tests for the statement-digest projection.
//!
//! These pin the two things a later circuit cannot renegotiate: byte order and injectivity. The
//! injection tests are also the reason the statement digest is field-sized — a reduced digest would
//! have several preimages per scalar, so the projection refuses it instead.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use cube_argo::{statement_public_input, ArgoAdapterError};

/// Returns the BN254 scalar-field modulus as a 32-byte big-endian digest.
fn modulus_digest() -> [u8; 32] {
    let bytes = <Fr as PrimeField>::MODULUS.to_bytes_be();
    assert!(bytes.len() <= 32, "the modulus must fit in 32 bytes");

    let mut digest = [0u8; 32];
    digest[32 - bytes.len()..].copy_from_slice(&bytes);
    digest
}

/// Adds one to a big-endian digest in place.
fn increment_be(digest: &mut [u8; 32]) {
    for byte in digest.iter_mut().rev() {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            return;
        }
    }
    panic!("the digest must not overflow 256 bits");
}

/// Subtracts one from a big-endian digest in place.
fn decrement_be(digest: &mut [u8; 32]) {
    for byte in digest.iter_mut().rev() {
        let (next, borrow) = byte.overflowing_sub(1);
        *byte = next;
        if !borrow {
            return;
        }
    }
    panic!("the digest must not underflow");
}

#[test]
fn projection_is_big_endian() {
    // 1 Zero maps to zero.
    assert_eq!(
        statement_public_input([0u8; 32]).expect("zero is field-sized"),
        Fr::from(0u64)
    );

    // 2 The last byte is the least significant one.
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(
        statement_public_input(one).expect("one is field-sized"),
        Fr::from(1u64)
    );

    // 3 The first byte is the most significant one.
    let mut high = [0u8; 32];
    high[0] = 1;
    assert_eq!(
        statement_public_input(high).expect("2^248 is field-sized"),
        Fr::from(2u64).pow([248u64])
    );
}

#[test]
fn projection_refuses_anything_the_conversion_would_reduce() {
    // 1 The modulus itself would reduce to zero.
    let modulus = modulus_digest();
    assert_eq!(
        statement_public_input(modulus),
        Err(ArgoAdapterError::StatementDigestNotBelowModulus { digest: modulus })
    );

    // 2 Just above the modulus would reduce to one.
    let mut above = modulus;
    increment_be(&mut above);
    assert_eq!(
        statement_public_input(above),
        Err(ArgoAdapterError::StatementDigestNotBelowModulus { digest: above })
    );

    // 3 An unmasked 32-byte value is not a `CubeV1/Statement/v1` digest at all.
    let unmasked = [0xffu8; 32];
    assert_eq!(
        statement_public_input(unmasked),
        Err(ArgoAdapterError::StatementDigestNotBelowModulus { digest: unmasked })
    );
}

#[test]
fn projection_accepts_the_largest_field_sized_value_and_stays_injective() {
    // 1 `r - 1` is accepted and maps to `-1`, not to something smaller: no reduction happened.
    let mut below = modulus_digest();
    decrement_be(&mut below);
    assert_eq!(
        statement_public_input(below).expect("r - 1 is field-sized"),
        -Fr::from(1u64)
    );

    // 2 The pair that collided under the old reduction: zero and the modulus. Zero is accepted, the
    //   modulus is refused, so the collision cannot be constructed.
    assert_eq!(
        statement_public_input([0u8; 32]).expect("zero is field-sized"),
        Fr::from(0u64)
    );
    assert!(statement_public_input(modulus_digest()).is_err());

    // 3 Every digest the statement definition can produce (top three bits cleared) is accepted.
    let mut masked = [0xffu8; 32];
    masked[0] &= 0x1f;
    assert!(statement_public_input(masked).is_ok());
}
