use ark_bn254::{Fq, g2};
use ark_ec::short_weierstrass::Affine;
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};

use crate::garble::{g2_subgroup_check, groth16_verifier::KAPPA_B};
use std::fmt::Debug;

fn deserialize_box_vec<T, const N: usize, R>(
    mut reader: R,
    compress: Compress,
    validate: Validate,
) -> Result<Box<[T; N]>, SerializationError>
where
    T: CanonicalDeserialize + Debug,
    R: std::io::Read,
{
    let mut vec = Vec::with_capacity(N);
    for _ in 0..N {
        vec.push(T::deserialize_with_mode(&mut reader, compress, validate)?);
    }

    Ok(vec.into_boxed_slice().try_into().expect("N elements"))
}

impl CanonicalSerialize for g2_subgroup_check::Table {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.enc_s.serialize_with_mode(&mut writer, compress)?;
        self.r_ks.serialize_with_mode(&mut writer, compress)?;

        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.enc_s.serialized_size(compress) + self.r_ks.serialized_size(compress)
    }
}

impl CanonicalDeserialize for g2_subgroup_check::Table {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let enc_s = Fq::deserialize_with_mode(&mut reader, compress, validate)?;

        // These are not g2 points, so don't validate that they are in the
        // subgroup
        let r_ks = deserialize_box_vec::<Affine<g2::Config>, { KAPPA_B }, _>(
            &mut reader,
            compress,
            Validate::No,
        )?;

        Ok(Self { enc_s, r_ks })
    }
}

impl Valid for g2_subgroup_check::Table {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}
