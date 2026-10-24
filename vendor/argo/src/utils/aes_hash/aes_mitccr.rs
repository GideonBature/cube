//! miTCCR construction from Section 4.2 https://eprint.iacr.org/2019/1168.pdf

#[cfg(test)]
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

use aes::{
    Aes128,
    cipher::{BlockEncryptMut, KeyInit},
};

use crate::utils::aes_hash::{AES_BLOCK_SIZE, Hash};

#[derive(Debug, Clone)]
pub(crate) struct AesMiTCCR;

impl AesMiTCCR {
    /// σ(xL‖xR) = xR ⊕ xL ‖ xL, from https://eprint.iacr.org/2019/074.pdf
    fn sigma(x: &[u8]) -> [u8; AES_BLOCK_SIZE] {
        let x_l = &x[..AES_BLOCK_SIZE / 2];
        let x_r = &x[(AES_BLOCK_SIZE / 2)..];

        let mut output = [0; AES_BLOCK_SIZE];
        output
            .iter_mut()
            .zip(x_l.iter())
            .zip(x_r.iter())
            .for_each(|((out, l), r)| *out = l ^ r);

        output[(AES_BLOCK_SIZE / 2)..].copy_from_slice(x_l);

        output
    }
}

impl Hash for AesMiTCCR {
    /// This is used as a hash function that takes in hash(key, message)
    /// where:
    ///     - key: gid XOR nonce
    ///     - msg: input_mac
    ///
    /// AES(key, σ(msg)) XOR σ(msg)
    fn hash(key: &[u8; 16], msg: &[u8; 16]) -> [u8; 16] {
        let mut hasher = Aes128::new(key.into());
        let sigma_msg = Self::sigma(msg);

        #[cfg(test)]
        // Check that each msg is used only once per key.
        assert!(
            COUNTERS_MAP.with(|map| { map.borrow_mut().entry(*key).or_default().insert(*msg) })
        );

        let mut block = sigma_msg;
        hasher.encrypt_block_mut((&mut block).into());

        block
            .iter_mut()
            .zip(sigma_msg.iter())
            .for_each(|(block, pad)| *block ^= pad);

        block
    }
}

#[cfg(test)]
thread_local! {
    /// Mapping from seed to set of used counters; a counter should be used
    /// only once per seed
    pub(crate) static COUNTERS_MAP: RefCell<BTreeMap<[u8; AES_BLOCK_SIZE], BTreeSet<[u8; AES_BLOCK_SIZE]>>> = const { RefCell::new(BTreeMap::new()) }
}

#[cfg(test)]
/// Clear the set
pub(crate) fn clear_set() {
    COUNTERS_MAP.with(|map| {
        map.borrow_mut().clear();
    });
}
