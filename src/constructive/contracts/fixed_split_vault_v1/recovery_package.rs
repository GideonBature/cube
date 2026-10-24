//! The claim recovery package.
//!
//! A recovery package is everything a fresh client needs to recover a beneficiary claim without the
//! Engine, the original device, or any service. It carries the claim's identity, the statement it
//! is bound to, the exact script and control block that spend it, and the economic terms needed to
//! judge whether spending it is still correct.
//!
//! Two claim shapes are supported. A v1 package describes the single-leaf claim; a v2 package
//! carries the assertion binding digest as well, so it describes the two-leaf claim that adds an
//! `Assert` branch while keeping the recovery branch. The recovery spend is the same in both cases:
//! the carried recovery script and its control block.
//!
//! # Why the script and control block are inside the package
//!
//! Deriving them from the statement and beneficiary key is possible, but it makes recovery depend on
//! this crate's template code being present and unchanged. Carrying the bytes makes the package
//! self-describing: a recovery implementation in another language can spend the claim from the
//! package alone. `validate` then proves the carried bytes are consistent with the carried
//! statement, so self-description cannot drift into self-delusion.
//!
//! # What this package does not provide
//!
//! - **Data availability.** A package is a local artifact. Nothing here publishes it, and a hash on
//!   chain is not publication (specification.md section 10).
//! - **Proof material.** `setup_instance_id`, `challenge_config_digest`, the statement digest and a
//!   v2 binding are carried so a later assertion can be matched against them. Proof, table and
//!   authenticated-input bytes are not included; `docs/bind_01.md` covers their availability.
//! - **Encryption.** The package contains no secret keys, but it is not encrypted or authenticated.
//!   Integrity is checked structurally; authenticity needs a signature the protocol has not defined.

use crate::constructive::contracts::fixed_split_vault_v1::claim::{
    assertion_claim_control_block, assertion_claim_scriptpubkey, claim_control_block, claim_script,
    claim_scriptpubkey, parse_claim_script, CLAIM_RECOVERY_LEAF_INDEX,
};
use crate::model::fixed_split_vault_v1::manifest::Anchor;
use crate::model::fixed_split_vault_v1::ReleaseProfile;
use crate::transmutative::hash::{Hash, HashTag};
use bitcoin::taproot::ControlBlock;
use bitcoin::ScriptBuf;

/// The schema version byte of the single-leaf package encoding.
pub const PACKAGE_SCHEMA_VERSION: u8 = 1;

/// The schema version byte of the two-leaf claim package encoding.
///
/// The only encoding difference is the assertion binding digest: v2 carries it directly after the
/// statement digest, v1 does not. Both versions remain decodable so an old package keeps working.
pub const PACKAGE_SCHEMA_VERSION_V2: u8 = 2;

/// The BIP-340 style tagged-hash tag of the package digest.
pub const PACKAGE_DIGEST_TAG: &str = "CubeV1/Package/v0";

/// Whether the claim has already been spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DischargeState {
    /// The claim is live and must be recovered.
    Undischarged,
    /// The claim has been spent. Retained for audit, never recoverable again.
    Discharged,
}

impl DischargeState {
    /// Returns the frozen encoding tag.
    pub fn tag(self) -> u8 {
        match self {
            DischargeState::Undischarged => 0x00,
            DischargeState::Discharged => 0x01,
        }
    }

    /// Returns the state of a frozen encoding tag.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x00 => Some(DischargeState::Undischarged),
            0x01 => Some(DischargeState::Discharged),
            _ => None,
        }
    }
}

/// Everything needed to recover one beneficiary claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimRecoveryPackage {
    /// The schema version of this encoding.
    pub schema_version: u8,
    /// The release profile the claim belongs to.
    pub profile: ReleaseProfile,
    /// The stable claim identity.
    pub claim_id: [u8; 32],
    /// The claim this one replaced, when a refresh happened.
    pub predecessor_claim_id: Option<[u8; 32]>,
    /// The only key that can spend the claim.
    pub beneficiary_key: [u8; 32],
    /// The template the claim was created under.
    pub template_hash: [u8; 32],
    /// The circuit identity the statement belongs to.
    pub circuit_id: [u8; 32],
    /// The statement commitment the claim binds.
    pub statement_digest: [u8; 32],
    /// The assertion binding digest for a two-leaf claim, or `None` for a single-leaf v1 claim.
    pub assertion_binding_digest: Option<[u8; 32]>,

    /// The value the claim pays, in satoshis.
    pub entitlement_sats: u64,
    /// Whether the claim is still live.
    pub discharge: DischargeState,
    /// The outpoint holding the claim, once funded.
    pub claim_outpoint: Option<Anchor>,
    /// The height after which the claim should be treated as stale.
    pub expiry_height: u64,
    /// The fee rate the recovery spend was authorised to pay.
    pub fee_rate_sat_per_vb: u64,

    /// The setup instance the assertion must belong to.
    pub setup_instance_id: [u8; 32],
    /// The challenge and timing configuration digest.
    pub challenge_config_digest: [u8; 32],

    /// The recovery claim tapscript, as carried rather than re-derived.
    pub claim_script: Vec<u8>,
    /// The control block that commits `claim_script` to the claim output.
    pub control_block: Vec<u8>,
}

impl ClaimRecoveryPackage {
    /// Constructs a single-leaf (v1) package, deriving the script and control block.
    ///
    /// `decode` exists for importing a package whose bytes came from elsewhere.
    pub fn new(
        profile: ReleaseProfile,
        claim_id: [u8; 32],
        predecessor_claim_id: Option<[u8; 32]>,
        beneficiary_key: [u8; 32],
        template_hash: [u8; 32],
        circuit_id: [u8; 32],
        statement_digest: [u8; 32],
        entitlement_sats: u64,
        claim_outpoint: Option<Anchor>,
        expiry_height: u64,
        fee_rate_sat_per_vb: u64,
        setup_instance_id: [u8; 32],
        challenge_config_digest: [u8; 32],
    ) -> Option<Self> {
        Self::build(
            profile,
            claim_id,
            predecessor_claim_id,
            beneficiary_key,
            template_hash,
            circuit_id,
            statement_digest,
            entitlement_sats,
            claim_outpoint,
            expiry_height,
            fee_rate_sat_per_vb,
            setup_instance_id,
            challenge_config_digest,
            None,
        )
    }

    /// Constructs a two-leaf (v2) package for a claim that also carries an assertion leaf.
    ///
    /// The recovery leaf and the beneficiary key are unchanged; only the taproot has a second leaf
    /// and therefore a different output key and control block.
    pub fn new_with_assertion(
        profile: ReleaseProfile,
        claim_id: [u8; 32],
        predecessor_claim_id: Option<[u8; 32]>,
        beneficiary_key: [u8; 32],
        template_hash: [u8; 32],
        circuit_id: [u8; 32],
        statement_digest: [u8; 32],
        assertion_binding_digest: [u8; 32],
        entitlement_sats: u64,
        claim_outpoint: Option<Anchor>,
        expiry_height: u64,
        fee_rate_sat_per_vb: u64,
        setup_instance_id: [u8; 32],
        challenge_config_digest: [u8; 32],
    ) -> Option<Self> {
        Self::build(
            profile,
            claim_id,
            predecessor_claim_id,
            beneficiary_key,
            template_hash,
            circuit_id,
            statement_digest,
            entitlement_sats,
            claim_outpoint,
            expiry_height,
            fee_rate_sat_per_vb,
            setup_instance_id,
            challenge_config_digest,
            Some(assertion_binding_digest),
        )
    }

    /// Builds the package and derives the control block for the claim shape the binding selects.
    #[allow(clippy::too_many_arguments)]
    fn build(
        profile: ReleaseProfile,
        claim_id: [u8; 32],
        predecessor_claim_id: Option<[u8; 32]>,
        beneficiary_key: [u8; 32],
        template_hash: [u8; 32],
        circuit_id: [u8; 32],
        statement_digest: [u8; 32],
        entitlement_sats: u64,
        claim_outpoint: Option<Anchor>,
        expiry_height: u64,
        fee_rate_sat_per_vb: u64,
        setup_instance_id: [u8; 32],
        challenge_config_digest: [u8; 32],
        assertion_binding_digest: Option<[u8; 32]>,
    ) -> Option<Self> {
        let claim_script = claim_script(statement_digest, beneficiary_key);
        let (schema_version, control_block) = match assertion_binding_digest {
            Some(binding) => (
                PACKAGE_SCHEMA_VERSION_V2,
                assertion_claim_control_block(
                    statement_digest,
                    binding,
                    beneficiary_key,
                    CLAIM_RECOVERY_LEAF_INDEX,
                )?,
            ),
            None => (
                PACKAGE_SCHEMA_VERSION,
                claim_control_block(statement_digest, beneficiary_key)?,
            ),
        };

        Some(Self {
            schema_version,
            profile,
            claim_id,
            predecessor_claim_id,
            beneficiary_key,
            template_hash,
            circuit_id,
            statement_digest,
            assertion_binding_digest,
            entitlement_sats,
            discharge: DischargeState::Undischarged,
            claim_outpoint,
            expiry_height,
            fee_rate_sat_per_vb,
            setup_instance_id,
            challenge_config_digest,
            claim_script,
            control_block,
        })
    }

    /// Validates the package.
    ///
    /// The important check is the cross-field one: the carried script must commit to the carried
    /// statement digest and beneficiary key, and the carried control block must commit that script
    /// to the output key the scriptpubkey specifies. A package that fails this is not a claim.
    pub fn validate(&self) -> Result<(), PackageError> {
        // 1 Schema version, and the binding the version requires.
        match self.schema_version {
            PACKAGE_SCHEMA_VERSION => {
                if self.assertion_binding_digest.is_some() {
                    return Err(PackageError::UnexpectedAssertionBinding);
                }
            }
            PACKAGE_SCHEMA_VERSION_V2 => {
                let binding = self
                    .assertion_binding_digest
                    .ok_or(PackageError::MissingAssertionBinding)?;
                if binding == [0u8; 32] {
                    return Err(PackageError::ZeroAssertionBinding);
                }
            }
            actual => return Err(PackageError::UnsupportedSchemaVersion { actual }),
        }

        // 2 Economy and timing must be usable.
        if self.entitlement_sats == 0 {
            return Err(PackageError::ZeroEntitlement);
        }
        if self.fee_rate_sat_per_vb == 0 {
            return Err(PackageError::ZeroFeeRate);
        }
        if self.expiry_height == 0 {
            return Err(PackageError::ZeroExpiryHeight);
        }
        if self.beneficiary_key == [0u8; 32] {
            return Err(PackageError::ZeroBeneficiaryKey);
        }

        // 3 The carried script must be the recovery claim script for exactly this statement and key.
        let expected_script = claim_script(self.statement_digest, self.beneficiary_key);
        if self.claim_script != expected_script {
            return Err(PackageError::ClaimScriptMismatch);
        }
        let (script_digest, script_key) =
            parse_claim_script(&self.claim_script).ok_or(PackageError::ClaimScriptMismatch)?;
        if script_digest != self.statement_digest || script_key != self.beneficiary_key {
            return Err(PackageError::ClaimScriptMismatch);
        }

        // 4 The control block must commit the script to the claim output key.
        let scriptpubkey = self
            .claim_scriptpubkey()
            .ok_or(PackageError::ClaimScriptpubkeyUnavailable)?;
        let output_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&scriptpubkey[2..])
            .map_err(|_| PackageError::ClaimScriptpubkeyUnavailable)?;
        let control_block = ControlBlock::decode(&self.control_block)
            .map_err(|_| PackageError::InvalidControlBlock)?;
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        if !control_block.verify_taproot_commitment(
            &secp,
            output_key,
            &ScriptBuf::from_bytes(self.claim_script.clone()),
        ) {
            return Err(PackageError::ControlBlockDoesNotCommit);
        }

        // 5 A discharged claim must not claim to be live.
        if self.discharge == DischargeState::Discharged && self.claim_outpoint.is_none() {
            return Err(PackageError::DischargedWithoutOutpoint);
        }

        Ok(())
    }

    /// Returns the claim scriptpubkey this package recovers.
    pub fn claim_scriptpubkey(&self) -> Option<Vec<u8>> {
        match self.assertion_binding_digest {
            Some(binding) => {
                assertion_claim_scriptpubkey(self.statement_digest, binding, self.beneficiary_key)
            }
            None => claim_scriptpubkey(self.statement_digest, self.beneficiary_key),
        }
    }

    /// Returns the canonical encoding of the package.
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::<u8>::with_capacity(512);

        // 1 Identity and terms.
        buffer.push(self.schema_version);
        buffer.push(self.profile.tag());
        buffer.extend(self.claim_id);
        match &self.predecessor_claim_id {
            Some(predecessor) => {
                buffer.push(1);
                buffer.extend(predecessor);
            }
            None => buffer.push(0),
        }
        buffer.extend(self.beneficiary_key);
        buffer.extend(self.template_hash);
        buffer.extend(self.circuit_id);
        buffer.extend(self.statement_digest);
        if self.schema_version == PACKAGE_SCHEMA_VERSION_V2 {
            buffer.extend(self.assertion_binding_digest.unwrap_or([0u8; 32]));
        }

        // 2 Economy.
        buffer.extend(self.entitlement_sats.to_le_bytes());
        buffer.push(self.discharge.tag());
        match &self.claim_outpoint {
            Some(anchor) => {
                buffer.push(1);
                buffer.extend(anchor.txid);
                buffer.extend(anchor.vout.to_le_bytes());
            }
            None => buffer.push(0),
        }
        buffer.extend(self.expiry_height.to_le_bytes());
        buffer.extend(self.fee_rate_sat_per_vb.to_le_bytes());

        // 3 Enforcement.
        buffer.extend(self.setup_instance_id);
        buffer.extend(self.challenge_config_digest);

        // 4 Self-describing spend material.
        buffer.extend((self.claim_script.len() as u16).to_le_bytes());
        buffer.extend(&self.claim_script);
        buffer.extend((self.control_block.len() as u16).to_le_bytes());
        buffer.extend(&self.control_block);

        buffer
    }

    /// Decodes and validates the canonical encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, PackageError> {
        let mut reader = PackageReader::new(bytes);

        // 1 Identity and terms.
        let schema_version = reader.u8()?;
        if schema_version != PACKAGE_SCHEMA_VERSION && schema_version != PACKAGE_SCHEMA_VERSION_V2 {
            return Err(PackageError::UnsupportedSchemaVersion {
                actual: schema_version,
            });
        }
        let profile_tag = reader.u8()?;
        let profile = ReleaseProfile::from_tag(profile_tag)
            .ok_or(PackageError::UnknownProfileTag(profile_tag))?;
        let claim_id = reader.key()?;
        let predecessor_claim_id = match reader.u8()? {
            0 => None,
            1 => Some(reader.key()?),
            flag => return Err(PackageError::UnknownPresenceFlag(flag)),
        };
        let beneficiary_key = reader.key()?;
        let template_hash = reader.key()?;
        let circuit_id = reader.key()?;
        let statement_digest = reader.key()?;
        let assertion_binding_digest = if schema_version == PACKAGE_SCHEMA_VERSION_V2 {
            Some(reader.key()?)
        } else {
            None
        };

        // 2 Economy.
        let entitlement_sats = reader.u64()?;
        let discharge_tag = reader.u8()?;
        let discharge = DischargeState::from_tag(discharge_tag)
            .ok_or(PackageError::UnknownDischargeTag(discharge_tag))?;
        let claim_outpoint = match reader.u8()? {
            0 => None,
            1 => Some(Anchor {
                txid: reader.key()?,
                vout: reader.u32()?,
            }),
            flag => return Err(PackageError::UnknownPresenceFlag(flag)),
        };
        let expiry_height = reader.u64()?;
        let fee_rate_sat_per_vb = reader.u64()?;

        // 3 Enforcement.
        let setup_instance_id = reader.key()?;
        let challenge_config_digest = reader.key()?;

        // 4 Self-describing spend material.
        let claim_script_len = reader.u16()? as usize;
        let claim_script = reader.take(claim_script_len)?.to_vec();
        let control_block_len = reader.u16()? as usize;
        let control_block = reader.take(control_block_len)?.to_vec();

        // 5 Reject trailing bytes.
        if reader.remaining() != 0 {
            return Err(PackageError::TrailingBytes {
                decoded: reader.offset(),
                actual: bytes.len(),
            });
        }

        // 6 Reject a package that does not describe a real claim.
        let package = Self {
            schema_version,
            profile,
            claim_id,
            predecessor_claim_id,
            beneficiary_key,
            template_hash,
            circuit_id,
            statement_digest,
            assertion_binding_digest,
            entitlement_sats,
            discharge,
            claim_outpoint,
            expiry_height,
            fee_rate_sat_per_vb,
            setup_instance_id,
            challenge_config_digest,
            claim_script,
            control_block,
        };
        package.validate()?;

        Ok(package)
    }

    /// Returns the tagged digest of the package, for inventory and transport checks.
    ///
    /// This is an integrity identifier, not an authenticator: it proves the bytes arrived intact,
    /// not who produced them.
    pub fn digest(&self) -> [u8; 32] {
        self.encode()
            .hash(Some(HashTag::CustomString(PACKAGE_DIGEST_TAG.to_string())))
    }

    /// Returns whether the package still needs recovery.
    pub fn is_recoverable(&self) -> bool {
        self.discharge == DischargeState::Undischarged && self.claim_outpoint.is_some()
    }

    /// Returns whether the package should be treated as stale at the given height.
    pub fn is_stale_at(&self, height: u64) -> bool {
        height >= self.expiry_height
    }
}

/// Deterministic rejection reasons of the recovery package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageError {
    /// The schema version is not a supported version.
    UnsupportedSchemaVersion { actual: u8 },
    /// A v2 package does not carry the assertion binding digest.
    MissingAssertionBinding,
    /// A v1 package carries an assertion binding digest.
    UnexpectedAssertionBinding,
    /// The assertion binding digest is all zeroes.
    ZeroAssertionBinding,
    /// The profile tag is not a frozen profile.
    UnknownProfileTag(u8),
    /// The discharge tag is not a frozen state.
    UnknownDischargeTag(u8),
    /// A presence flag is neither zero nor one.
    UnknownPresenceFlag(u8),
    /// The entitlement is zero.
    ZeroEntitlement,
    /// The authorised fee rate is zero.
    ZeroFeeRate,
    /// The expiry height is zero.
    ZeroExpiryHeight,
    /// The beneficiary key is the all-zero key.
    ZeroBeneficiaryKey,
    /// A discharged claim carries no outpoint.
    DischargedWithoutOutpoint,
    /// The carried script is not the claim script for the carried statement and key.
    ClaimScriptMismatch,
    /// The claim scriptpubkey could not be derived.
    ClaimScriptpubkeyUnavailable,
    /// The carried control block does not decode.
    InvalidControlBlock,
    /// The carried control block does not commit the carried script.
    ControlBlockDoesNotCommit,
    /// The byte string ended before the field at `offset` could be read.
    Truncated { offset: usize, needed: usize },
    /// The byte string continued after the package was complete.
    TrailingBytes { decoded: usize, actual: usize },
}

/// A bounds-checked little-endian reader over a byte slice.
struct PackageReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PackageReader<'a> {
    /// Creates a reader over the given bytes.
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Returns the number of bytes consumed so far.
    fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the number of bytes not yet consumed.
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    /// Takes exactly `count` bytes or reports truncation.
    fn take(&mut self, count: usize) -> Result<&'a [u8], PackageError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(PackageError::Truncated {
                offset: self.offset,
                needed: count,
            })?;

        if end > self.bytes.len() {
            return Err(PackageError::Truncated {
                offset: self.offset,
                needed: count,
            });
        }

        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    /// Reads one byte.
    fn u8(&mut self) -> Result<u8, PackageError> {
        Ok(self.take(1)?[0])
    }

    /// Reads one little-endian `u16`.
    fn u16(&mut self) -> Result<u16, PackageError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Reads one little-endian `u32`.
    fn u32(&mut self) -> Result<u32, PackageError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads one little-endian `u64`.
    fn u64(&mut self) -> Result<u64, PackageError> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(array))
    }

    /// Reads one 32-byte key.
    fn key(&mut self) -> Result<[u8; 32], PackageError> {
        let bytes = self.take(32)?;
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(array)
    }
}
