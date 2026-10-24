use crate::model::fixed_split_vault_v1::types::Role;
use crate::transmutative::hash::{Hash, HashTag};

/// The BIP-340 style tagged-hash tag of the statement commitment.
///
/// Frozen: changing it changes every proof statement and every assertion a Bitcoin output commits
/// to, so it must be versioned rather than edited.
pub const STATEMENT_DIGEST_TAG: &str = "CubeV1/Statement/v0";

/// The schema version byte of the frozen manifest encoding.
pub const MANIFEST_SCHEMA_VERSION: u8 = 1;

/// The maximum number of funding or claim anchors one manifest may bind.
pub const MAX_ANCHORS: usize = 4;

/// The maximum number of ordered payout obligations one manifest may bind.
pub const MAX_PAYOUTS: usize = 4;

/// The release profile a manifest belongs to (specification.md section 1).
///
/// Tags are frozen because they enter the signed statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseProfile {
    /// The payment baseline on its own.
    PaymentsV1,
    /// The payment baseline plus the `FixedSplitVaultV1` pilot.
    ArgoSplitRegtest,
    /// The second pilot, `FixedHashlockEscrowV1`.
    ArgoEscrowRegtest,
}

impl ReleaseProfile {
    /// Returns the frozen encoding tag of the profile.
    pub fn tag(self) -> u8 {
        match self {
            ReleaseProfile::PaymentsV1 => 0x00,
            ReleaseProfile::ArgoSplitRegtest => 0x01,
            ReleaseProfile::ArgoEscrowRegtest => 0x02,
        }
    }

    /// Returns the profile of a frozen encoding tag.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x00 => Some(ReleaseProfile::PaymentsV1),
            0x01 => Some(ReleaseProfile::ArgoSplitRegtest),
            0x02 => Some(ReleaseProfile::ArgoEscrowRegtest),
            _ => None,
        }
    }
}

/// What an ordered payout obligation is for.
///
/// This is the minimum needed to describe the `FixedSplitVaultV1` transition: two beneficiary
/// allocations and one disclosed execution fee. It is not a general-purpose payout taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayoutKind {
    /// A beneficiary's shadow allocation, still held inside the contract.
    BeneficiaryAllocation,
    /// The disclosed execution fee, paid to the fee account.
    ExecutionFee,
    /// A beneficiary's native successor claim, after redemption.
    NativeSuccessor,
}

impl PayoutKind {
    /// Returns the frozen encoding tag of the payout kind.
    pub fn tag(self) -> u8 {
        match self {
            PayoutKind::BeneficiaryAllocation => 0x00,
            PayoutKind::ExecutionFee => 0x01,
            PayoutKind::NativeSuccessor => 0x02,
        }
    }

    /// Returns the payout kind of a frozen encoding tag.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x00 => Some(PayoutKind::BeneficiaryAllocation),
            0x01 => Some(PayoutKind::ExecutionFee),
            0x02 => Some(PayoutKind::NativeSuccessor),
            _ => None,
        }
    }
}

/// One ordered payout obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Payout {
    /// The exact recipient key.
    pub recipient_key: [u8; 32],
    /// The amount in satoshis. Always strictly positive.
    pub amount_sats: u64,
    /// What the payout is for.
    pub kind: PayoutKind,
}

impl Payout {
    /// Constructs a payout obligation.
    pub fn new(recipient_key: [u8; 32], amount_sats: u64, kind: PayoutKind) -> Self {
        Self {
            recipient_key,
            amount_sats,
            kind,
        }
    }
}

/// One funding or claim anchor outpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Anchor {
    /// The transaction id, in the same byte order the signed bytes use.
    ///
    /// The display-order reversal of a txid MUST NOT reach this field; the adapter that fills a
    /// manifest is responsible for using serialized bytes.
    pub txid: [u8; 32],
    /// The output index.
    pub vout: u32,
}

impl Anchor {
    /// Constructs an anchor.
    pub fn new(txid: [u8; 32], vout: u32) -> Self {
        Self { txid, vout }
    }
}

/// The canonical description of one accepted state transition.
///
/// This is the object the proof statement commits to and the object a Bitcoin output must bind to.
/// Its field groups follow specification.md section 7.1; fields the bounded pilot does not yet
/// constrain are listed in `open_gaps` on the struct documentation below rather than silently
/// omitted.
///
/// # What this type deliberately does not do
///
/// - It does **not** derive itself from a `SplitVault` transition. A derivation function has to
///   decide how obligations and fee rules are computed, which is design work with its own review.
/// - It does **not** implement the Argo public-input mapping `x = OS2IP_BE(D) mod r`. That mapping
///   is unassessed under CRYPTO-01 and committing to it here would imply a settled construction.
/// - It does **not** include the consumed-operation set, for the same reason the state digest does
///   not: it is unbounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionManifest {
    /// The schema version of this encoding.
    pub schema_version: u8,
    /// The release profile this transition belongs to.
    pub profile: ReleaseProfile,
    /// The genesis hash of the target Bitcoin network.
    pub network_genesis_hash: [u8; 32],
    /// The hash of the compiled allowlisted template.
    pub template_hash: [u8; 32],
    /// The circuit identity the relation is frozen at.
    pub circuit_id: [u8; 32],
    /// The digest of the Groth16 verifier key.
    pub verifier_key_digest: [u8; 32],

    /// The accepted state digest the transition starts from.
    pub previous_state_digest: [u8; 32],
    /// The accepted state digest the transition produces.
    pub resulting_state_digest: [u8; 32],
    /// The stable batch sequence number.
    pub batch_sequence: u64,
    /// The funding or claim outpoints the transition spends.
    pub anchors: Vec<Anchor>,

    /// The digest of the entry that authorised the transition.
    pub entry_digest: [u8; 32],
    /// The caller that authorised the entry.
    pub caller_key: [u8; 32],
    /// The caller authorization sequence, already advanced by this transition.
    pub caller_sequence: u64,
    /// The stable operation identity, used for retry and replay protection.
    pub operation_id: [u8; 32],

    /// The ordered payout obligations, in output order.
    pub payouts: Vec<Payout>,

    /// The garbling or setup instance the assertion belongs to.
    pub setup_instance_id: [u8; 32],
    /// The graph template version.
    pub graph_template_version: u16,
    /// The digest of the challenge and timing configuration.
    pub challenge_config_digest: [u8; 32],
    /// The commitment to the recovery package for this claim.
    pub recovery_package_digest: [u8; 32],

    /// The digest of the canonical batch or data payload.
    pub batch_data_digest: [u8; 32],
    /// The commitment to the availability or package descriptor.
    pub availability_descriptor_digest: [u8; 32],
}

impl TransitionManifest {
    /// Validates the manifest before it is encoded or committed to.
    ///
    /// Rejections are checked in this frozen order so that two implementations agree on the error:
    ///
    /// 1. schema version
    /// 2. anchor count and anchor distinctness
    /// 3. payout count, zero amounts, zero keys and duplicate recipients
    pub fn validate(&self) -> Result<(), ManifestError> {
        // 1 Require the frozen schema version.
        if self.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedSchemaVersion {
                actual: self.schema_version,
            });
        }

        // 2 Require between one and `MAX_ANCHORS` distinct anchors.
        if self.anchors.is_empty() || self.anchors.len() > MAX_ANCHORS {
            return Err(ManifestError::AnchorCount {
                count: self.anchors.len(),
            });
        }
        for (index, anchor) in self.anchors.iter().enumerate() {
            if self.anchors[..index].contains(anchor) {
                return Err(ManifestError::DuplicateAnchor { index });
            }
        }

        // 3 Require between one and `MAX_PAYOUTS` payouts with distinct, nonzero recipients.
        if self.payouts.is_empty() || self.payouts.len() > MAX_PAYOUTS {
            return Err(ManifestError::PayoutCount {
                count: self.payouts.len(),
            });
        }
        for (index, payout) in self.payouts.iter().enumerate() {
            if payout.recipient_key == [0u8; 32] {
                return Err(ManifestError::ZeroRecipient { index });
            }
            if payout.amount_sats == 0 {
                return Err(ManifestError::ZeroAmount { index });
            }
            if self.payouts[..index]
                .iter()
                .any(|other| other.recipient_key == payout.recipient_key)
            {
                return Err(ManifestError::DuplicateRecipient { index });
            }
        }

        Ok(())
    }

    /// Returns the canonical encoding of the manifest.
    ///
    /// Every integer is fixed-width little-endian; the two bounded vectors carry a one-byte count.
    /// There are no optional or reserved fields, so a manifest has exactly one encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::<u8>::with_capacity(512);

        // 1 Context.
        buffer.push(self.schema_version);
        buffer.push(self.profile.tag());
        buffer.extend(self.network_genesis_hash);
        buffer.extend(self.template_hash);
        buffer.extend(self.circuit_id);
        buffer.extend(self.verifier_key_digest);

        // 2 Parent.
        buffer.extend(self.previous_state_digest);
        buffer.extend(self.resulting_state_digest);
        buffer.extend(self.batch_sequence.to_le_bytes());
        buffer.push(self.anchors.len() as u8);
        for anchor in self.anchors.iter() {
            buffer.extend(anchor.txid);
            buffer.extend(anchor.vout.to_le_bytes());
        }

        // 3 Execution.
        buffer.extend(self.entry_digest);
        buffer.extend(self.caller_key);
        buffer.extend(self.caller_sequence.to_le_bytes());
        buffer.extend(self.operation_id);

        // 4 Entitlements.
        buffer.push(self.payouts.len() as u8);
        for payout in self.payouts.iter() {
            buffer.extend(payout.recipient_key);
            buffer.extend(payout.amount_sats.to_le_bytes());
            buffer.push(payout.kind.tag());
        }

        // 5 Enforcement.
        buffer.extend(self.setup_instance_id);
        buffer.extend(self.graph_template_version.to_le_bytes());
        buffer.extend(self.challenge_config_digest);
        buffer.extend(self.recovery_package_digest);

        // 6 Data availability.
        buffer.extend(self.batch_data_digest);
        buffer.extend(self.availability_descriptor_digest);

        buffer
    }

    /// Decodes the canonical encoding.
    ///
    /// Truncation, trailing bytes, unknown tags and any manifest that fails `validate` are
    /// rejected rather than normalised.
    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let mut reader = Reader::new(bytes);

        // 1 Context.
        let schema_version = reader.u8()?;
        let profile_tag = reader.u8()?;
        let profile = ReleaseProfile::from_tag(profile_tag)
            .ok_or(ManifestError::UnknownProfileTag(profile_tag))?;
        let network_genesis_hash = reader.key()?;
        let template_hash = reader.key()?;
        let circuit_id = reader.key()?;
        let verifier_key_digest = reader.key()?;

        // 2 Parent.
        let previous_state_digest = reader.key()?;
        let resulting_state_digest = reader.key()?;
        let batch_sequence = reader.u64()?;
        let anchor_count = reader.u8()? as usize;
        if anchor_count == 0 || anchor_count > MAX_ANCHORS {
            return Err(ManifestError::AnchorCount {
                count: anchor_count,
            });
        }
        let mut anchors = Vec::<Anchor>::with_capacity(anchor_count);
        for _ in 0..anchor_count {
            let txid = reader.key()?;
            let vout = reader.u32()?;
            anchors.push(Anchor { txid, vout });
        }

        // 3 Execution.
        let entry_digest = reader.key()?;
        let caller_key = reader.key()?;
        let caller_sequence = reader.u64()?;
        let operation_id = reader.key()?;

        // 4 Entitlements.
        let payout_count = reader.u8()? as usize;
        if payout_count == 0 || payout_count > MAX_PAYOUTS {
            return Err(ManifestError::PayoutCount {
                count: payout_count,
            });
        }
        let mut payouts = Vec::<Payout>::with_capacity(payout_count);
        for _ in 0..payout_count {
            let recipient_key = reader.key()?;
            let amount_sats = reader.u64()?;
            let kind_tag = reader.u8()?;
            let kind = PayoutKind::from_tag(kind_tag)
                .ok_or(ManifestError::UnknownPayoutKindTag(kind_tag))?;
            payouts.push(Payout {
                recipient_key,
                amount_sats,
                kind,
            });
        }

        // 5 Enforcement.
        let setup_instance_id = reader.key()?;
        let graph_template_version = reader.u16()?;
        let challenge_config_digest = reader.key()?;
        let recovery_package_digest = reader.key()?;

        // 6 Data availability.
        let batch_data_digest = reader.key()?;
        let availability_descriptor_digest = reader.key()?;

        // 7 Reject trailing bytes.
        if reader.remaining() != 0 {
            return Err(ManifestError::TrailingBytes {
                decoded: reader.offset(),
                actual: bytes.len(),
            });
        }

        // 8 Reject a manifest that no accepted transition could produce.
        let manifest = Self {
            schema_version,
            profile,
            network_genesis_hash,
            template_hash,
            circuit_id,
            verifier_key_digest,
            previous_state_digest,
            resulting_state_digest,
            batch_sequence,
            anchors,
            entry_digest,
            caller_key,
            caller_sequence,
            operation_id,
            payouts,
            setup_instance_id,
            graph_template_version,
            challenge_config_digest,
            recovery_package_digest,
            batch_data_digest,
            availability_descriptor_digest,
        };
        manifest.validate()?;

        Ok(manifest)
    }

    /// Returns the commitment `D` that a proof statement and a Bitcoin assertion must bind.
    ///
    /// This is a tagged hash over the canonical encoding, not the Argo public input. The reduction
    /// `x = OS2IP_BE(D) mod r` is a separate, unassessed step (CRYPTO-01) and is intentionally not
    /// implemented here.
    pub fn statement_digest(&self) -> [u8; 32] {
        self.encode().hash(Some(HashTag::CustomString(
            STATEMENT_DIGEST_TAG.to_string(),
        )))
    }

    /// Returns the total value of all payout obligations as a wide integer.
    ///
    /// Wide so that a manifest with several large payouts cannot wrap the sum during accounting
    /// checks.
    pub fn total_payout_sats(&self) -> u128 {
        self.payouts
            .iter()
            .map(|payout| u128::from(payout.amount_sats))
            .sum()
    }

    /// Returns the index of the payout to a recipient, if present.
    pub fn payout_index_of(&self, recipient_key: [u8; 32]) -> Option<usize> {
        self.payouts
            .iter()
            .position(|payout| payout.recipient_key == recipient_key)
    }

    /// Returns the role a payout index is expected to belong to in the split-vault profile.
    ///
    /// Provided so a reviewer can compare the obligation order against the reference model without
    /// re-deriving it.
    pub fn expected_roles() -> [Role; 3] {
        [Role::Bob, Role::Carol, Role::Fee]
    }
}

/// Deterministic rejection reasons of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The schema version is not the frozen version.
    UnsupportedSchemaVersion { actual: u8 },
    /// The anchor count is outside the accepted bound.
    AnchorCount { count: usize },
    /// Two anchor slots refer to the same outpoint.
    DuplicateAnchor { index: usize },
    /// The payout count is outside the accepted bound.
    PayoutCount { count: usize },
    /// A payout recipient key is the all-zero key.
    ZeroRecipient { index: usize },
    /// A payout amount is zero.
    ZeroAmount { index: usize },
    /// Two payouts name the same recipient.
    DuplicateRecipient { index: usize },
    /// The profile tag is not a frozen profile.
    UnknownProfileTag(u8),
    /// The payout kind tag is not a frozen kind.
    UnknownPayoutKindTag(u8),
    /// The byte string ended before the field at `offset` could be read.
    Truncated { offset: usize, needed: usize },
    /// The byte string continued after the manifest was complete.
    TrailingBytes { decoded: usize, actual: usize },
}

/// A bounds-checked little-endian reader over a byte slice.
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
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
    fn take(&mut self, count: usize) -> Result<&'a [u8], ManifestError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ManifestError::Truncated {
                offset: self.offset,
                needed: count,
            })?;

        if end > self.bytes.len() {
            return Err(ManifestError::Truncated {
                offset: self.offset,
                needed: count,
            });
        }

        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    /// Reads one byte.
    fn u8(&mut self) -> Result<u8, ManifestError> {
        Ok(self.take(1)?[0])
    }

    /// Reads one little-endian `u16`.
    fn u16(&mut self) -> Result<u16, ManifestError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Reads one little-endian `u32`.
    fn u32(&mut self) -> Result<u32, ManifestError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads one little-endian `u64`.
    fn u64(&mut self) -> Result<u64, ManifestError> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(array))
    }

    /// Reads one 32-byte key.
    fn key(&mut self) -> Result<[u8; 32], ManifestError> {
        let bytes = self.take(32)?;
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(array)
    }
}
