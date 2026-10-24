use std::{marker::PhantomData, ops::Neg};

use ark_bn254::{Bn254, Fq12, g1, g2};
use ark_ec::{
    pairing::Pairing,
    scalar_mul::glv::GLVConfig,
    short_weierstrass::{Affine, SWCurveConfig},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::mac::{ddh::DDHMac, endo::EndoMac, group::GroupMac};

pub(crate) mod pairing;
pub(crate) mod scalar_mul;

pub(crate) trait BilinearOp<G1, G2: SWCurveConfig> {
    fn bilinear_op(g1: G1, g2: Affine<G2>) -> Self;
}

impl<C: SWCurveConfig> BilinearOp<C::ScalarField, C> for Affine<C> {
    fn bilinear_op(scalar: C::ScalarField, curve_point: Affine<C>) -> Self {
        (curve_point * scalar).into()
    }
}

impl BilinearOp<Affine<g1::Config>, g2::Config> for Fq12 {
    fn bilinear_op(g1: Affine<g1::Config>, g2: Affine<g2::Config>) -> Self {
        Bn254::pairing(g1, g2).0
    }
}

pub(crate) trait TargetOp {
    fn target_op(&self, other: Self) -> Self;
}

impl<C: SWCurveConfig> TargetOp for Affine<C> {
    fn target_op(&self, other: Self) -> Self {
        (*self + other).into()
    }
}

impl TargetOp for Fq12 {
    fn target_op(&self, other: Self) -> Self {
        self * other
    }
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub(crate) struct Table<G1, G2, Gt, const KAPPA: usize>
where
    G1: Send + Sync,
    G2: SWCurveConfig,
    Gt: BilinearOp<G1, G2> + TargetOp + Send + Sync,
{
    pub(crate) T: [Affine<G2>; KAPPA],
    _marker: PhantomData<(G1, Gt)>,
}

impl<G1, G2, Gt, const KAPPA: usize> Table<G1, G2, Gt, KAPPA>
where
    G1: Send + Sync + Copy,
    G2: GLVConfig,
    Gt: BilinearOp<G1, G2>
        + TargetOp
        + Send
        + Sync
        + CanonicalSerialize
        + CanonicalDeserialize
        + Neg,
{
    fn evaluate(
        &self,
        input: &G1,
        input_mac: &GroupMac<G1>,
        ddh_mac: &DDHMac<G2, KAPPA>,
    ) -> Vec<EndoMac<G2, Gt>> {
        self.T
            .iter()
            .zip(ddh_mac.0.iter())
            .map(|(t, s)| {
                EndoMac::from(
                    Gt::bilinear_op(**input_mac, *t).target_op(Gt::bilinear_op(*input, *s)),
                )
            })
            .collect()
    }
}
