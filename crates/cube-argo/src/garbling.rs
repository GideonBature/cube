//! Garbling setup and evaluation over Argo's Groth16 verifier table.
//!
//! Setup turns a converted verifier key plus a disclosure secret into an opaque table that reveals
//! the secret exactly when the equation fails. Evaluation returns one of three outcomes and never
//! interprets "nonzero" as evidence by itself:
//!
//! ```text
//! Accepted   the equation held; nothing was disclosed
//! Disclosed  the equation failed and the configured secret came out
//! Unexpected the table returned neither, which no correct table should do
//! ```
//!
//! # Seed handling
//!
//! Upstream's public constructor takes one `u64` seed and derives a `StdRng` from it twice: once for
//! the input MAC key and once for the garbling itself. Passing the same seed to both would make the
//! MAC key the first bytes of the garbling stream, so setup derives two independent seeds from the
//! configured seed with a domain-separated hash. That fixes the reuse, not the ceiling: a `u64`
//! seed carries at most 64 bits, which is an upstream API limit and is recorded as an open defect
//! rather than hidden.
//!
//! # What setup assumes
//!
//! Several verifier keys may be used in one process: the vendored Argo keys its preprocessing cache
//! by the verifier key (`vendor/argo/PATCHES.md` item 1), so a second key cannot inherit the first
//! key's pairing powers. A table is still bound to exactly one key, and [`GarbledVerifier::evaluate`]
//! discloses on proofs made for another key — `tests/garbling.rs` checks both directions.
//!
//! The disclosure secret must not be zero, because `Fq::ZERO` is Argo's "no disclosure" sentinel.
//! [`GarblingConfig::validate`] enforces that before any table exists.
//!
//! # Stack
//!
//! Setup recurses through Argo's table hierarchy and keeps `[Fq12; 254]` precomputations on the
//! stack. The default 2 MiB thread stack is not enough: a debug build overflows it inside
//! [`GarbledVerifier::setup`]. Run setup on a thread with at least
//! [`RECOMMENDED_SETUP_STACK_BYTES`]; evaluation needs no such accommodation.

use argo::garble::groth16_verifier::{garble_groth16, Input, InputMacKey, Table};
use argo::garble::{Circuit, Nonce};
use argo::mac::MacKey;
use ark_bn254::Fq;
use ark_ff::AdditiveGroup;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};

use crate::{ArgoAdapterError, GarblingConfig, PreparedVerifierKey, VerifierKeyIdentity};

/// The global identifier of one garbling instance, matching Argo's `GID`.
pub type SetupInstanceId = [u8; 16];

/// The stack size setup needs, in bytes.
///
/// Measured, not chosen for comfort: the default 2 MiB test-thread stack overflows inside Argo's
/// garbling in a debug build. 64 MiB leaves room for the recursion plus the `[Fq12; 254]`
/// precomputation the verifier key keeps on the stack.
pub const RECOMMENDED_SETUP_STACK_BYTES: usize = 64 * 1024 * 1024;

/// What one evaluation of a garbled verifier established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierOutcome {
    /// The equation held: the proof was accepted and no secret was disclosed.
    Accepted,
    /// The equation failed and the configured disclosure secret came out.
    Disclosed,
    /// The table returned a value that is neither zero nor the configured secret.
    ///
    /// No correct table should produce this. It is surfaced instead of being coerced into
    /// [`Self::Accepted`] or [`Self::Disclosed`], because either coercion would turn a broken table
    /// into a settled verdict.
    Unexpected(Fq),
}

/// A garbled Groth16 verifier bound to one verifier key and one instance identifier.
pub struct GarbledVerifier {
    /// Argo's table. Opaque: no accessor is provided on purpose.
    table: Table,
    /// The input MAC key the table was garbled against.
    input_mac_key: InputMacKey,
    /// The verifier-key identity this table belongs to.
    key_identity: VerifierKeyIdentity,
    /// The instance identifier carried into the table.
    instance_id: SetupInstanceId,
    /// The secret the table discloses on failure.
    disclosure_secret: Fq,
}

impl GarbledVerifier {
    /// Garbles a verifier key into a table that discloses `config.disclosure_secret` on failure.
    ///
    /// Any number of keys may be garbled in one process; each table is bound to the key it was
    /// garbled from, and its identity is reported by [`Self::key_identity`].
    pub fn setup(
        config: &GarblingConfig,
        key: &PreparedVerifierKey,
        instance_id: SetupInstanceId,
    ) -> Result<Self, ArgoAdapterError> {
        // Validate entropy and secret before touching Argo. A zero seed makes the whole setup
        // reproducible; a zero secret is indistinguishable from "nothing was disclosed".
        let disclosure_secret = config.disclosure_secret_field()?;

        let key_identity = key.identity();
        let verifier_key = key.to_argo_verifier_key()?;

        // Domain-separate the two uses of the configured seed. See the module documentation.
        let mut mac_rng = StdRng::seed_from_u64(derive_seed(b"input-mac-key", config.rng_seed));
        let input_mac_key = InputMacKey::random_key(&mut mac_rng);

        let table = garble_groth16(
            derive_seed(b"garbling", config.rng_seed),
            disclosure_secret,
            verifier_key,
            &input_mac_key,
            instance_id,
        )
        .map_err(|_| ArgoAdapterError::GarblingFailed)?;

        Ok(Self {
            table,
            input_mac_key,
            key_identity,
            instance_id,
            disclosure_secret,
        })
    }

    /// Evaluates the garbled verifier on one proof and public scalar.
    ///
    /// A fresh [`Nonce`] is used per evaluation; reusing one would corrupt Argo's counters.
    pub fn evaluate(
        &self,
        proof: &crate::Groth16Proof,
    ) -> Result<VerifierOutcome, ArgoAdapterError> {
        let input = Input {
            A: proof.a.into(),
            B: proof.b.into(),
            C: proof.c.into(),
            x: proof.x,
        };
        let input_mac = self.input_mac_key.encode(&input);

        let (output, _output_mac) = self
            .table
            .evaluate(&mut Nonce::new(), &input, &input_mac)
            .map_err(|_| ArgoAdapterError::EvaluationFailed)?;

        Ok(if output == Fq::ZERO {
            VerifierOutcome::Accepted
        } else if output == self.disclosure_secret {
            VerifierOutcome::Disclosed
        } else {
            VerifierOutcome::Unexpected(output)
        })
    }

    /// Returns the verifier-key identity this table was garbled against.
    pub fn key_identity(&self) -> VerifierKeyIdentity {
        self.key_identity
    }

    /// Returns the instance identifier the table was garbled with.
    pub fn instance_id(&self) -> SetupInstanceId {
        self.instance_id
    }

    /// Returns the compressed size of the serialized table in bytes.
    ///
    /// Recorded so that deployment material size can be measured instead of estimated. The bytes
    /// themselves are not exposed: a table handed out carelessly is a table that can be evaluated
    /// by anyone.
    pub fn serialized_size(&self) -> Result<usize, ArgoAdapterError> {
        let mut buffer = Vec::new();
        self.table
            .serialize_compressed(&mut buffer)
            .map_err(|_| ArgoAdapterError::SerializationFailed)?;
        Ok(buffer.len())
    }
}

/// Derives an independent 64-bit seed for one purpose from a configured seed.
///
/// Domain separation matters here because upstream seeds two different mechanisms from one `u64`.
/// The output is still 64 bits; that ceiling comes from Argo's API and is not raised by hashing.
fn derive_seed(domain: &[u8], rng_seed: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"Cube/Argo/Seed/v0");
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    hasher.update(rng_seed.to_le_bytes());
    let digest = hasher.finalize();

    let mut seed = [0u8; 8];
    seed.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(seed)
}
