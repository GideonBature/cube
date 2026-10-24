//! Given an `input_mac_key` and a value `phi`, derives an `output_mac_key`.
//! Maps the MAC of a single bit under input_mac_key to its MAC under the
//! derived output_mac_key.

pub(crate) mod bytes;
pub(crate) mod group;

use std::fmt::Debug;
#[cfg(test)]
use std::{cell::RefCell, collections::BTreeSet};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{
    garble::{Nonce, groth16_verifier::GID},
    mac::{Encrypt, Mac, Random},
    utils::{aes_hash::Hash, error::GarbleError},
};

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug)]
pub(crate) struct Table<H: Hash, InputMac, OutputMac>
where
    InputMac: Mac<bool> + Encrypt<H, OutputMac>,
    OutputMac: Mac<bool>,
    InputMac::Key: DeriveOutputMacKey<H, bool, bool, InputMac, OutputMac>,
    <InputMac as Encrypt<H, OutputMac>>::Ciphertext: Debug,
{
    gid: Option<GID>,
    pub(crate) ciphertext: <InputMac as Encrypt<H, OutputMac>>::Ciphertext,
}

pub(crate) trait DeriveOutputMacKey<H: Hash, Input, Output, InputMac, OutputMac>
where
    InputMac: Mac<Input>,
    OutputMac: Mac<Output>,
{
    /// Phi of output MAC key
    type Phi: Random;

    fn derive_output_mac_key(
        &self,
        dst: Option<&[u8; 16]>,
        parent_nonce: &Nonce,
        phi: &Self::Phi,
    ) -> Result<OutputMac::Key, GarbleError>;
}

#[cfg(test)]
thread_local! {
    /// Ciphertexts used in bit adaptor tables.
    pub(crate) static CIPHERTEXT_SET: RefCell<BTreeSet<Vec<u8>>> = const { RefCell::new(BTreeSet::new()) }
}

#[cfg(test)]
/// Clear the set
pub(crate) fn clear_set() {
    CIPHERTEXT_SET.with(|set| {
        set.borrow_mut().clear();
    });
}
