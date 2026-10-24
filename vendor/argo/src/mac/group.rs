use ark_ff::AdditiveGroup;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::StdRng;
use derive_more::{Deref, From};

use crate::mac::{Mac, MacKey, Random, RandomFromPhi};

#[derive(Clone, Copy, CanonicalDeserialize, CanonicalSerialize)]
pub(crate) struct GroupMacKey<G: AdditiveGroup> {
    pub(crate) phi: G,
    pub(crate) k: G,
}

#[derive(Deref, Debug, PartialEq, From)]
pub(crate) struct GroupMac<G>(pub(crate) G);

impl<G> Mac<G::Scalar> for GroupMac<G>
where
    G: AdditiveGroup + Random,
{
    type Key = GroupMacKey<G>;

    #[cfg(test)]
    fn random_input(rng: &mut StdRng) -> G::Scalar {
        use ark_ff::UniformRand;
        G::Scalar::rand(rng)
    }
}

impl<G> RandomFromPhi<G::Scalar, GroupMac<G>> for GroupMacKey<G>
where
    G: AdditiveGroup + Random,
{
    type Phi = G;

    fn random_from_phi(rng: &mut StdRng, phi: &G) -> Self {
        Self {
            phi: *phi,
            k: G::rand(rng),
        }
    }
}

impl<G> MacKey<G::Scalar, GroupMac<G>> for GroupMacKey<G>
where
    G: AdditiveGroup + Random,
{
    fn encode(&self, value: &G::Scalar) -> GroupMac<G> {
        GroupMac(self.phi * value + self.k)
    }

    #[cfg(test)]
    fn decode(&self, _mac: &GroupMac<G>) -> G::Scalar {
        unimplemented!()
    }

    fn random_key(rng: &mut StdRng) -> Self {
        let phi = G::rand(rng);
        <Self as RandomFromPhi<G::Scalar, GroupMac<G>>>::random_from_phi(rng, &phi)
    }
}
