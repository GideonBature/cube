use derive_more::Deref;
use std::marker::PhantomData;

use crate::mac::Mac;

/// DigitMAC where the underlying BitMACs are [u8; 16] bytestrings
pub(crate) mod bytes;
/// DigitMAC where the underlying BitMACs are group elements
pub(crate) mod group;

/// A MAC for the bits of a digit in G.
#[derive(Debug, Clone, PartialEq, Deref)]
pub(crate) struct DigitMac<G, BitMac>
where
    BitMac: Mac<bool>,
{
    #[deref]
    mac: Vec<BitMac>,
    _marker: PhantomData<G>,
}

impl<G, BitMac> From<Vec<BitMac>> for DigitMac<G, BitMac>
where
    BitMac: Mac<bool>,
{
    fn from(mac: Vec<BitMac>) -> Self {
        Self {
            mac,
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deref)]
/// MAC key for the bits of a digit
pub(crate) struct DigitMacKey<G, BitMac>
where
    BitMac: Mac<bool>,
{
    #[deref]
    key: Vec<BitMac::Key>,
    _marker: PhantomData<G>,
}

impl<G, BitMac> From<Vec<BitMac::Key>> for DigitMacKey<G, BitMac>
where
    BitMac: Mac<bool>,
{
    fn from(key: Vec<BitMac::Key>) -> Self {
        Self {
            key,
            _marker: PhantomData,
        }
    }
}
