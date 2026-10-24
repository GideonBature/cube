use derive_more::Deref;
use std::marker::PhantomData;

use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};

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

// PATCH(cube): the bit MACs are what an assertion publishes so a party without the input MAC key
// can evaluate the table. `PhantomData<G>` has no arkworks encoding, so the encoding is the inner
// vector and nothing else. The field type and its length are fixed by the proof encoding, which is
// what makes the byte string canonical.
impl<G, BitMac> CanonicalSerialize for DigitMac<G, BitMac>
where
    BitMac: Mac<bool> + CanonicalSerialize,
{
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.mac.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.mac.serialized_size(compress)
    }
}

impl<G, BitMac> Valid for DigitMac<G, BitMac>
where
    G: Sync,
    BitMac: Mac<bool> + Valid,
{
    fn check(&self) -> Result<(), SerializationError> {
        self.mac.check()
    }
}

impl<G, BitMac> CanonicalDeserialize for DigitMac<G, BitMac>
where
    G: Sync,
    BitMac: Mac<bool> + CanonicalDeserialize,
{
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(Self {
            mac: Vec::<BitMac>::deserialize_with_mode(reader, compress, validate)?,
            _marker: PhantomData,
        })
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
