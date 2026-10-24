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
//! # Who evaluates
//!
//! Argo authenticates the proof input with a MAC derived from the input MAC key. An evaluator that
//! holds the key can evaluate any input; one that holds only a *single* input and its MAC can
//! evaluate exactly that input and nothing else. That distinction is what an on-chain assertion
//! needs: the prover keeps the key, publishes one [`AuthenticatedInput`], and any challenger can
//! reproduce the outcome -- and learn the disclosure secret only when the published input is
//! invalid. [`GarbledVerifier::authenticate`] produces the published pair and
//! [`GarbledVerifier::evaluate_authenticated`] consumes it without the key.
//!
//! That is not enough by itself. A MAC made for a different input is not evidence: an inner table's
//! decode fails and evaluation returns [`ArgoAdapterError::EvaluationFailed`] before the
//! conditional reveal, so a substituted input yields an error rather than the secret.
//! `tests/garbling.rs` records that result instead of assuming a disclosure. The on-chain binding
//! therefore also signs the published bytes; see `docs/bind_01.md` section 2.
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

use argo::garble::groth16_verifier::{garble_groth16, Input, InputMac, InputMacKey, Table};
use argo::garble::{Circuit, Nonce};
use argo::mac::MacKey;
use ark_bn254::{Fq, Fr};
use ark_ec::AffineRepr;
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use sha2::{Digest, Sha256};

use crate::{
    ArgoAdapterError, GarblingConfig, Groth16Proof, PreparedVerifierKey, VerifierKeyIdentity,
};

/// The global identifier of one garbling instance, matching Argo's `GID`.
pub type SetupInstanceId = [u8; 16];

/// The BIP-340 style tag of the authenticated-input digest.
///
/// The digest commits the exact proof input and its MAC, so an assertion cannot publish one pair
/// and be evaluated on another.
pub const AUTHENTICATED_INPUT_TAG: &str = "CubeV1/AuthenticatedInput/v0";

/// The BIP-340 style tag of the garbling-table digest.
pub const GARBLING_TABLE_TAG: &str = "CubeV1/GarblingTable/v0";

/// A published proof input and the MAC that authenticates it.
///
/// This is the unit an assertion commits to. It carries both halves because a party without the
/// input MAC key cannot evaluate the table on a bare input: the MAC is what makes the table treat
/// the values as the ones the prover was authorised to submit.
///
/// The encoding is length-prefixed canonical bytes:
///
/// ```text
/// u32 LE(input length) || Input canonical bytes
/// u32 LE(MAC length)   || InputMac canonical bytes
/// ```
///
/// Both inner encodings are fixed-length for a BN254 verifier (288 and 36,632 bytes at this
/// revision), but the prefixes keep the format decodable without pinning those numbers in this
/// crate's API. [`AuthenticatedInput::from_bytes`] re-encodes what it decoded, so a second encoding
/// of the same value is rejected instead of being silently accepted as a different commitment.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedInput {
    bytes: Vec<u8>,
}

impl core::fmt::Debug for AuthenticatedInput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The bytes are tens of kilobytes; printing them would drown every log line that mentions
        // an assertion. The digest identifies the value.
        formatter
            .debug_struct("AuthenticatedInput")
            .field("bytes", &self.bytes.len())
            .field("digest", &hex_prefix(&self.digest()))
            .finish()
    }
}

impl AuthenticatedInput {
    /// Wraps published bytes after checking that they decode canonically.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ArgoAdapterError> {
        let candidate = Self {
            bytes: bytes.to_vec(),
        };
        let (input, mac) = candidate.decode()?;
        let canonical = encode_authenticated_input(&input, &mac)?;
        if canonical != candidate.bytes {
            return Err(ArgoAdapterError::InvalidAuthenticatedInput);
        }
        Ok(candidate)
    }

    /// Returns the published bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a copy of the published bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Returns the tagged digest an assertion commits to.
    pub fn digest(&self) -> [u8; 32] {
        tagged_hash(AUTHENTICATED_INPUT_TAG, &self.bytes)
    }

    /// Returns the public scalar the input carries.
    ///
    /// The caller still has to check that this scalar is the statement it means to assert; the
    /// adapter does not know which statement is expected.
    pub fn public_input(&self) -> Result<Fr, ArgoAdapterError> {
        Ok(self.decode()?.0.x)
    }

    /// Decodes the published bytes into Argo's input pair.
    fn decode(&self) -> Result<(Input, InputMac), ArgoAdapterError> {
        let bytes = &self.bytes;
        let mut reader = ByteReader::new(bytes);

        let input_len = reader.u32()? as usize;
        let input = Input::deserialize_compressed(reader.take(input_len)?)
            .map_err(|_| ArgoAdapterError::InvalidAuthenticatedInput)?;

        let mac_len = reader.u32()? as usize;
        let mac = InputMac::deserialize_compressed(reader.take(mac_len)?)
            .map_err(|_| ArgoAdapterError::InvalidAuthenticatedInput)?;

        if reader.remaining() != 0 {
            return Err(ArgoAdapterError::InvalidAuthenticatedInput);
        }

        Ok((input, mac))
    }
}

/// A bounds-checked reader over the authenticated-input encoding.
struct ByteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ByteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ArgoAdapterError> {
        let end = self
            .offset
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ArgoAdapterError::InvalidAuthenticatedInput)?;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u32(&mut self) -> Result<u32, ArgoAdapterError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

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
    /// The digest of the serialized table, committed by an assertion.
    table_digest: [u8; 32],
    /// The input MAC key the table was garbled against.
    ///
    /// This is the prover's material. Publishing it would let anyone authenticate an arbitrary
    /// invalid input, learn the disclosure secret and dispute a valid assertion.
    input_mac_key: InputMacKey,
    /// The verifier-key identity this table belongs to.
    key_identity: VerifierKeyIdentity,
    /// The instance identifier carried into the table.
    instance_id: SetupInstanceId,
    /// The secret the table discloses on failure.
    disclosure_secret: Fq,
    /// The commitment to that secret, published and checked by the dispute script.
    disclosure_secret_commitment: [u8; 32],
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

        // The table and the secret commitment are what an assertion publishes. They are computed
        // once here so a verifier or challenger never has to trust a value supplied alongside the
        // assertion.
        let mut table_bytes = Vec::new();
        table
            .serialize_compressed(&mut table_bytes)
            .map_err(|_| ArgoAdapterError::SerializationFailed)?;
        let table_digest = tagged_hash(GARBLING_TABLE_TAG, &table_bytes);
        let disclosure_secret_commitment = disclosure_commitment(disclosure_secret);

        Ok(Self {
            table,
            table_digest,
            input_mac_key,
            key_identity,
            instance_id,
            disclosure_secret,
            disclosure_secret_commitment,
        })
    }

    /// Evaluates the garbled verifier on one proof and public scalar.
    ///
    /// This is the prover's view: it authenticates the proof with the key it was set up with. A
    /// challenger uses [`Self::authenticate`] once (on the prover's side) and
    /// [`Self::evaluate_authenticated`] on the published bytes.
    ///
    /// A fresh [`Nonce`] is used per evaluation; reusing one would corrupt Argo's counters.
    pub fn evaluate(&self, proof: &Groth16Proof) -> Result<VerifierOutcome, ArgoAdapterError> {
        let input = proof_input(proof)?;
        let input_mac = self.input_mac_key.encode(&input);
        self.evaluate_parts(&input, &input_mac)
    }

    /// Authenticates one proof so the pair can be published with an assertion.
    ///
    /// The returned bytes are the only input the table will evaluate as this proof: a challenger
    /// cannot derive a MAC for a different input without the key.
    pub fn authenticate(
        &self,
        proof: &Groth16Proof,
    ) -> Result<AuthenticatedInput, ArgoAdapterError> {
        let input = proof_input(proof)?;
        let input_mac = self.input_mac_key.encode(&input);
        let bytes = encode_authenticated_input(&input, &input_mac)?;
        Ok(AuthenticatedInput { bytes })
    }

    /// Evaluates one published input without the input MAC key.
    ///
    /// This is what a challenger runs. It needs the table, which the assertion identifies by
    /// [`Self::table_digest`], and nothing else.
    pub fn evaluate_authenticated(
        &self,
        input: &AuthenticatedInput,
    ) -> Result<VerifierOutcome, ArgoAdapterError> {
        let (input, input_mac) = input.decode()?;
        self.evaluate_parts(&input, &input_mac)
    }

    /// Evaluates one decoded input pair and classifies the output.
    fn evaluate_parts(
        &self,
        input: &Input,
        input_mac: &InputMac,
    ) -> Result<VerifierOutcome, ArgoAdapterError> {
        let (output, _output_mac) = self
            .table
            .evaluate(&mut Nonce::new(), input, input_mac)
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

    /// Returns the tagged digest of the serialized table.
    ///
    /// An assertion commits this digest; a challenger checks the table it obtained hashes to it
    /// before evaluating. Without that check the challenger could be evaluating a table the
    /// prover chose after seeing the challenge.
    pub fn table_digest(&self) -> [u8; 32] {
        self.table_digest
    }

    /// Returns the tagged commitment to the disclosure secret.
    ///
    /// A `Disprove` tapscript checks a revealed preimage against this digest. The bytes are the
    /// canonical little-endian encoding of the field element the table returns on failure.
    pub fn disclosure_secret_commitment(&self) -> [u8; 32] {
        self.disclosure_secret_commitment
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

/// Encodes the canonical authenticated-input byte string.
fn encode_authenticated_input(
    input: &Input,
    input_mac: &InputMac,
) -> Result<Vec<u8>, ArgoAdapterError> {
    let mut input_bytes = Vec::new();
    input
        .serialize_compressed(&mut input_bytes)
        .map_err(|_| ArgoAdapterError::SerializationFailed)?;

    let mut mac_bytes = Vec::new();
    input_mac
        .serialize_compressed(&mut mac_bytes)
        .map_err(|_| ArgoAdapterError::SerializationFailed)?;

    let mut bytes = Vec::with_capacity(8 + input_bytes.len() + mac_bytes.len());
    bytes.extend((input_bytes.len() as u32).to_le_bytes());
    bytes.extend(&input_bytes);
    bytes.extend((mac_bytes.len() as u32).to_le_bytes());
    bytes.extend(&mac_bytes);

    Ok(bytes)
}

/// Converts a proof into Argo's bivariate input.
///
/// Argo encodes a group element as its affine coordinates, so the point at infinity has no input
/// representation. It is rejected instead of panicking; an assertion cannot publish such a proof
/// because there are no bytes to publish.
fn proof_input(proof: &Groth16Proof) -> Result<Input, ArgoAdapterError> {
    if proof.a.is_zero() || proof.b.is_zero() || proof.c.is_zero() {
        return Err(ArgoAdapterError::DegenerateProofComponent);
    }

    Ok(Input {
        A: proof.a.into(),
        B: proof.b.into(),
        C: proof.c.into(),
        x: proof.x,
    })
}

/// Returns the commitment to a disclosure secret.
///
/// The preimage is the canonical little-endian field encoding, not the caller's original byte
/// string: the table returns a field element, and a non-canonical input would otherwise admit
/// several commitments for one secret. The hash is plain SHA-256 because that is what the
/// `Disprove` tapscript computes; the instance binding lives in the assertion digest.
fn disclosure_commitment(secret: Fq) -> [u8; 32] {
    sha256(&secret.into_bigint().to_bytes_le())
}

/// Plain SHA-256.
fn sha256(message: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(message);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

/// BIP-340 style tagged SHA-256.
fn tagged_hash(tag: &str, message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(message);
    let digest = hasher.finalize();

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

/// Formats the first four bytes of a digest for logs.
fn hex_prefix(digest: &[u8; 32]) -> String {
    digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Returns the commitment to a canonical secret byte string.
///
/// This is the function a chain-side `Disprove` script mirrors. The bytes must be the canonical
/// little-endian field encoding; a non-canonical 32-byte string can represent a value that reduces
/// to the same secret, so it is refused rather than committed. `src/constructive/graph/assertion.rs`
/// pins the same golden vector.
pub fn disclosure_secret_commitment(secret_le: &[u8; 32]) -> Option<[u8; 32]> {
    let secret = Fq::from_le_bytes_mod_order(secret_le);
    if secret.into_bigint().to_bytes_le() != secret_le.as_slice() {
        return None;
    }
    Some(disclosure_commitment(secret))
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
