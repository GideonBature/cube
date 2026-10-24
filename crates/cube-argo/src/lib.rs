//! Adapter between Cube and Argo.
//!
//! Argo garbles a **Groth16 verifier equation** over BN254; it does not garble a program. Its inputs
//! are a prepared `VerifierKey`, a proof `(A, B, C)` and a single public scalar `x`. This crate owns
//! the boundary between Cube's protocol types and that equation, and nothing else.
//!
//! # Why this is a separate crate
//!
//! Argo is Rust edition 2024 on arkworks **0.5**, while Cube is edition 2021 on arkworks **0.4.2**
//! (pulled in by `bls_on_arkworks`). The two arkworks trees cannot share types, so every value that
//! crosses the boundary must cross as bytes. Keeping the adapter in its own crate makes that
//! boundary a build-time fact rather than a convention: Cube's default build cannot accidentally
//! depend on Argo types.
//!
//! # Upstream properties this adapter has to live with
//!
//! Verified at the pinned revision `aa28ba88`:
//!
//! 1. `groth16_verifier::garble_preprocess` caches `e(G, H1)^{2^i}` / `e(G, H2)^{2^i}` in a
//!    process-global `static PREPROCESSED_VK` and returns it **without checking which verifying key
//!    produced it**. Garbling a second, different key in the same process would silently reuse the
//!    first key's precomputation. [`VerifierKeyIdentity`] exists to make that impossible through
//!    this crate: one key identity per process, fail closed otherwise.
//! 2. `Table::evaluate` calls `input_validity::evaluate(..)?` and **discards** the returned `Fq`.
//!    That value is the disclosure secret on every input-validity failure path, so those failures do
//!    not contribute evidence to the output. This adapter does not paper over it; it is recorded as
//!    an open defect.
//! 3. `garble_groth16(rng_seed: u64, ..)` seeds `StdRng::seed_from_u64`. The public constructor
//!    therefore takes 64 bits of seed for the whole garbling. Setup must not use it with a guessable
//!    seed; [`GarblingConfig`] requires explicitly supplied entropy and refuses a zero seed.
//! 4. `Fq::ZERO` is Argo's "no disclosure" sentinel, so a zero disclosure secret must be rejected at
//!    setup or a valid proof and a disclosed secret become indistinguishable.
//!
//! # Contents
//!
//! - [`PreparedVerifierKey`]: the canonical-byte carrier for Argo's prepared equation.
//! - [`Groth16VerifyingKey`] and [`PreparedVerifierKey::from_groth16_verifying_key`]: the projection
//!   of a standard Groth16 key onto that equation, including the pairing signs Argo requires.
//! - [`GarblingConfig`]: the entropy and disclosure-secret preconditions for setup.
//! - [`GarbledVerifier`]: setup and evaluation of Argo's table, with a three-way outcome instead of
//!   a boolean.
//! - [`register_verifier_key_identity`]: the process-wide guard for upstream's unkeyed cache.

mod convert;
mod garbling;

pub use convert::{Groth16Proof, Groth16VerifyingKey};
pub use garbling::{
    GarbledVerifier, SetupInstanceId, VerifierOutcome, RECOMMENDED_SETUP_STACK_BYTES,
};

use argo::garble::groth16_verifier::VerifierKey;
use ark_bn254::{Fq, Fq12, G1Affine, G2Affine};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::sync::Mutex;

/// Errors raised by the adapter itself, before Argo is involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgoAdapterError {
    /// A zero disclosure secret was supplied.
    ///
    /// `Fq::ZERO` is Argo's "no disclosure" sentinel, so a zero secret would make a valid proof and
    /// a disclosed secret indistinguishable.
    ZeroDisclosureSecret,
    /// A zero RNG seed was supplied.
    ///
    /// The seed is only 64 bits; a constant or zero seed makes the garbling reproducible by anyone.
    ZeroRngSeed,
    /// A different verifier key was already registered in this process.
    ///
    /// Upstream caches the verifier preprocessing process-globally without keying it by the key, so
    /// a second identity would silently reuse the first key's precomputation.
    ConflictingVerifierKey {
        /// The identity already registered.
        registered: [u8; 32],
        /// The identity that was refused.
        rejected: [u8; 32],
    },
    /// The verifier key bytes did not decode.
    InvalidVerifierKeyBytes,
    /// The Groth16 key does not have exactly one public input.
    ///
    /// Argo's equation multiplies one `G1` point by one scalar, so a key with a different number of
    /// `gamma_abc_g1` entries cannot be represented without dropping or merging inputs.
    UnsupportedPublicInputCount {
        /// The number of `gamma_abc_g1` entries that was supplied.
        found: usize,
    },
    /// A verifier-key component cannot carry a nontrivial equation.
    ///
    /// Raised for a point at infinity in any component, and for a constant term that has no
    /// inverse. Either case would silently remove a constraint instead of failing the proof.
    DegenerateVerifierKey,
    /// The converted verifier key could not be encoded into canonical bytes.
    VerifierKeyEncoding,
    /// Argo refused to garble the table.
    GarblingFailed,
    /// Argo refused to evaluate the table on the supplied input.
    ///
    /// Upstream propagates malformed-input failures as errors and discards the disclosure value it
    /// computed on the way, so such a failure carries no evidence. That defect is upstream's, not
    /// this adapter's; see the module documentation.
    EvaluationFailed,
    /// The table could not be serialized for measurement.
    SerializationFailed,
    /// The disclosure secret bytes did not decode to a field element.
    InvalidDisclosureSecretBytes,
    /// No verifier key was registered before use.
    NoVerifierKeyRegistered,
}

/// A stable identity for one Groth16 verifying key, derived from its canonical bytes.
pub type VerifierKeyIdentity = [u8; 32];

/// The process-wide identity guard for Argo's global verifier preprocessing.
///
/// Upstream `garble_preprocess` stores its result in an unkeyed `static`. This guard is the only
/// supported way to reach Argo through this crate, and it permits exactly one verifier-key identity
/// per process.
static REGISTERED_VERIFIER_KEY: Mutex<Option<VerifierKeyIdentity>> = Mutex::new(None);

/// Registers the verifier-key identity for this process.
///
/// Re-registering the *same* identity is allowed and idempotent. Registering a different identity is
/// refused, because upstream would otherwise reuse the first key's precomputation.
pub fn register_verifier_key_identity(
    identity: VerifierKeyIdentity,
) -> Result<(), ArgoAdapterError> {
    let mut registered = REGISTERED_VERIFIER_KEY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    match *registered {
        None => {
            *registered = Some(identity);
            Ok(())
        }
        Some(existing) if existing == identity => Ok(()),
        Some(existing) => Err(ArgoAdapterError::ConflictingVerifierKey {
            registered: existing,
            rejected: identity,
        }),
    }
}

/// Clears the registered identity. Intended for tests that run in one process.
pub fn reset_verifier_key_identity() {
    let mut registered = REGISTERED_VERIFIER_KEY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *registered = None;
}

/// Returns the registered verifier-key identity, if any.
pub fn registered_verifier_key_identity() -> Option<VerifierKeyIdentity> {
    *REGISTERED_VERIFIER_KEY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The parameters a garbling instance is created from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarblingConfig {
    /// A 64-bit seed, explicitly supplied. Must not be zero.
    ///
    /// This mirrors upstream's interface. It is **not** a recommendation: 64 bits is not full
    /// entropy, so the seed must come from a cryptographic source and must never be reused across
    /// instances.
    pub rng_seed: u64,
    /// The disclosure secret, as canonical little-endian bytes.
    ///
    /// Must not be zero, and must not be reused across instances.
    pub disclosure_secret: Vec<u8>,
}

impl GarblingConfig {
    /// Validates the configuration before any garbling happens.
    pub fn validate(&self) -> Result<(), ArgoAdapterError> {
        if self.rng_seed == 0 {
            return Err(ArgoAdapterError::ZeroRngSeed);
        }

        let secret = Fq::from_le_bytes_mod_order(&self.disclosure_secret);
        // `from_le_bytes_mod_order` reduces, so compare the decoded value rather than the bytes:
        // a non-zero byte string can still reduce to zero.
        if secret == Fq::ZERO {
            return Err(ArgoAdapterError::ZeroDisclosureSecret);
        }

        Ok(())
    }

    /// Returns the disclosure secret as a field element, after validation.
    pub fn disclosure_secret_field(&self) -> Result<Fq, ArgoAdapterError> {
        self.validate()?;
        Ok(Fq::from_le_bytes_mod_order(&self.disclosure_secret))
    }
}

/// A prepared Argo verifier key, carried as canonical bytes.
///
/// Argo's `VerifierKey { G1, H1, H2, c }` is a *prepared equation*, not a standard Groth16
/// verifying key: `G1` is the group element the single public scalar multiplies, `H1` and `H2` are
/// the pairing partners of `C` and `[x]`, and `c` folds in the fixed terms. Deriving it from
/// `(alpha, beta, gamma, delta, ic)` is the converter's job; this type only carries the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedVerifierKey {
    /// Canonical serialization of Argo's `VerifierKey`.
    pub canonical_bytes: Vec<u8>,
}

impl PreparedVerifierKey {
    /// Wraps raw canonical bytes.
    pub fn from_canonical_bytes(canonical_bytes: Vec<u8>) -> Self {
        Self { canonical_bytes }
    }

    /// Decodes the bytes into Argo's verifier key.
    pub fn to_argo_verifier_key(&self) -> Result<VerifierKey, ArgoAdapterError> {
        VerifierKey::deserialize_uncompressed(self.canonical_bytes.as_slice())
            .map_err(|_| ArgoAdapterError::InvalidVerifierKeyBytes)
    }

    /// Encodes an Argo verifier key into this carrier.
    ///
    /// Used by the converter once a real Groth16 verifying key exists.
    pub fn from_argo_verifier_key(verifier_key: &VerifierKey) -> Option<Self> {
        let mut canonical_bytes = Vec::<u8>::new();
        verifier_key
            .serialize_uncompressed(&mut canonical_bytes)
            .ok()?;
        Some(Self { canonical_bytes })
    }

    /// Returns the identity of this key, for the process-wide guard.
    pub fn identity(&self) -> VerifierKeyIdentity {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"Cube/Argo/VerifierKey/v0");
        hasher.update(&self.canonical_bytes);
        let digest = hasher.finalize();
        let mut identity = [0u8; 32];
        identity.copy_from_slice(&digest);
        identity
    }

    /// Registers this key as the process's single Argo verifier key.
    pub fn register(&self) -> Result<VerifierKeyIdentity, ArgoAdapterError> {
        let identity = self.identity();
        register_verifier_key_identity(identity)?;
        Ok(identity)
    }
}

/// Builds a prepared verifier key from its four prepared components.
///
/// Low-level constructor. [`PreparedVerifierKey::from_groth16_verifying_key`] is the supported way
/// to obtain these components from a real key.
pub fn prepare_verifier_key(g1: G1Affine, h1: G2Affine, h2: G2Affine, c: Fq12) -> VerifierKey {
    VerifierKey {
        G1: g1,
        H1: h1,
        H2: h2,
        c,
    }
}
