//! Adaptor table from a Bit16ByteMac to another Bit16ByteMac.

/// Adaptor table using fixed-key AesCtr as the hash function. This should only
/// be used when the input MAC key has a unique random `phi`.
pub(crate) mod aes_ctr;

/// Adaptor table using re-keyed AES instantiation of miTCCR as hash function.
/// This can be called when the input MAC key shares the same `phi` with other
/// input MAC keys (i.e. in the free-XOR case).
pub(crate) mod aes_mitccr;
