use std::sync::LazyLock;

use ark_bn254::{Bn254, Fq2, Fq12, Fr, G1Projective, G2Projective, g1, g2};
use ark_ec::{AffineRepr, CurveConfig, PrimeGroup, pairing::Pairing, short_weierstrass::Affine};
use ark_ff::{BigInteger, Field, PrimeField};

/// Powers of 2 of e(G, H)
pub static TARGET_GENERATOR_POW_2: LazyLock<Vec<Fq12>> = LazyLock::new(|| {
    let target_generator = Bn254::multi_pairing(
        vec![<G1Projective as PrimeGroup>::generator()],
        vec![G2Projective::generator()],
    )
    .0;

    let mut powers = Vec::with_capacity(Fr::MODULUS_BIT_SIZE as usize);
    let mut p = target_generator;
    powers.push(p);
    for _ in 1..Fr::MODULUS_BIT_SIZE {
        p.square_in_place();
        powers.push(p);
    }
    powers
});

/// [r]P, where P is a point on E'/Fp2 with x-coordinate = 1
/// This unwrap cannot fail since this is a valid curve point.
pub static R_MUL_COFACTOR_GENERATOR: LazyLock<Affine<g2::Config>> = LazyLock::new(|| {
    (Affine::get_point_from_x_unchecked(Fq2::ONE, true)
        .unwrap()
        .mul_bigint(Fr::MODULUS))
    .into()
});

pub static G1_P_SQ_MOD_R: LazyLock<<g1::Config as CurveConfig>::ScalarField> =
    LazyLock::new(|| {
        let p =
        <<<g1::Config as CurveConfig>::BaseField as Field>::BasePrimeField as PrimeField>::MODULUS;
        let p_mod_r =
            <g1::Config as CurveConfig>::ScalarField::from_le_bytes_mod_order(&p.to_bytes_le());
        p_mod_r.square()
    });

pub static G2_P_SQ_MOD_R: LazyLock<<g2::Config as CurveConfig>::ScalarField> =
    LazyLock::new(|| {
        let p =
        <<<g2::Config as CurveConfig>::BaseField as Field>::BasePrimeField as PrimeField>::MODULUS;
        let p_mod_r =
            <g2::Config as CurveConfig>::ScalarField::from_le_bytes_mod_order(&p.to_bytes_le());
        p_mod_r.square()
    });
