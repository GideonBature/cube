//! Tests for the statement-digest projection.
//!
//! These pin the two things a later circuit cannot renegotiate: byte order and range handling. They
//! also demonstrate the loss, because a test that only showed agreement on small values would hide
//! exactly why CRYPTO-01 stays open.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use cube_argo::statement_public_input;

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
    assert_eq!(statement_public_input([0u8; 32]), Fr::from(0u64));

    // 2 The last byte is the least significant one.
    let mut one = [0u8; 32];
    one[31] = 1;
    assert_eq!(statement_public_input(one), Fr::from(1u64));

    // 3 The first byte is the most significant one.
    let mut high = [0u8; 32];
    high[0] = 1;
    assert_eq!(statement_public_input(high), Fr::from(2u64).pow([248u64]));

    // 4 Reversing the bytes changes the scalar. If the adapter used little-endian, cases 2 and 3
    //   would swap and this assertion would still pass; 3 is what pins the direction.
    let mut reversed = one;
    reversed.reverse();
    assert_ne!(
        statement_public_input(reversed),
        statement_public_input(one)
    );
}

#[test]
fn projection_reduces_the_modulus_and_leaves_smaller_values_alone() {
    let modulus = modulus_digest();

    // 1 The modulus itself maps to zero: reduction applies to the whole 256-bit integer.
    assert_eq!(statement_public_input(modulus), Fr::from(0u64));

    // 2 Just above the modulus wraps to one, not to some larger or truncated value.
    let mut above = modulus;
    increment_be(&mut above);
    assert_eq!(statement_public_input(above), Fr::from(1u64));

    // 3 Just below the modulus must survive unchanged. Over-reducing would turn it into zero.
    let mut below = modulus;
    decrement_be(&mut below);
    assert_eq!(statement_public_input(below), -Fr::from(1u64));
}

#[test]
fn projection_is_not_injective() {
    // Two different 32-byte digests, one scalar. This is why the scalar alone cannot bind a
    // manifest: a proof for one statement would satisfy the other's public input.
    let zero = [0u8; 32];
    let modulus = modulus_digest();

    assert_ne!(zero, modulus, "the two digests must actually differ");
    assert_eq!(
        statement_public_input(zero),
        statement_public_input(modulus),
        "the collision must be visible to the test, not assumed"
    );
}
