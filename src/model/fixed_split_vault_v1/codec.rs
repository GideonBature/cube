use crate::model::fixed_split_vault_v1::error::{SplitDecodeError, SplitVaultError};
use crate::model::fixed_split_vault_v1::instance::{SplitDescriptor, SplitInstance};
use crate::model::fixed_split_vault_v1::types::{Ledger, Phase, Role};
use crate::transmutative::hash::{Hash, HashTag};

/// The schema version byte of the frozen `cube-v1-fixed-v0` state encoding.
pub const SCHEMA_VERSION: u8 = 1;

/// The BIP-340 style tagged-hash tag of the canonical state digest.
pub const STATE_DIGEST_TAG: &str = "CubeV1/State/v0";

/// The canonical committed state of one split vault.
///
/// This is the bounded state a single-transition proof has to commit to: the four native account
/// balances, the four caller authorization sequences and, once instantiated, the one contract
/// instance. It is a pure value: two implementations that agree here agree on everything the
/// reference model treats as consensus state.
///
/// The consumed-operation record is deliberately *not* part of this structure. It is an unbounded
/// set, it is enforced by `SplitVault` as a local safety record, and committing it is an explicit
/// open item tied to INV-07 and specification.md section 5.1 rather than something this encoding
/// silently pretends to cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitState {
    /// The instantiated contract, or `None` before `InstantiateSplit`.
    pub instance: Option<SplitInstance>,
    /// The four native account balances.
    pub ledger: Ledger,
    /// The last consumed caller authorization sequence per canonical role slot.
    pub sequences: [u64; 4],
}

impl SplitState {
    /// Returns the canonical state encoding.
    ///
    /// Layout (frozen):
    ///
    /// ```text
    /// schema_version u8 = 1
    /// instance_presence u8 (0 or 1)
    /// [instance block, 277 bytes, present only when instance_presence == 1]
    /// ledger_owner u64 | ledger_bob u64 | ledger_carol u64 | ledger_fee u64
    /// sequence_owner u64 | sequence_bob u64 | sequence_carol u64 | sequence_fee u64
    /// ```
    ///
    /// Every integer is fixed-width little-endian. There are no optional, variable-length or
    /// reserved fields, so an inactive slot cannot be encoded in more than one way.
    pub fn encode(&self) -> Vec<u8> {
        // 1 Pre-allocate the exact final length so that the encoding cannot be extended later.
        let instance_len = match self.instance {
            Some(_) => 277,
            None => 0,
        };
        let mut buffer = Vec::<u8>::with_capacity(2 + instance_len + 64);

        // 2 Write the schema version.
        buffer.push(SCHEMA_VERSION);

        // 3 Write the instance presence flag and the instance block.
        match &self.instance {
            Some(instance) => {
                buffer.push(1);
                instance.encode_into(&mut buffer);
            }
            None => {
                buffer.push(0);
            }
        }

        // 4 Write the four native balances in canonical slot order.
        buffer.extend(self.ledger.owner_sats.to_le_bytes());
        buffer.extend(self.ledger.bob_sats.to_le_bytes());
        buffer.extend(self.ledger.carol_sats.to_le_bytes());
        buffer.extend(self.ledger.fee_sats.to_le_bytes());

        // 5 Write the four caller authorization sequences in canonical slot order.
        for sequence in self.sequences.iter() {
            buffer.extend(sequence.to_le_bytes());
        }

        // 6 Return the canonical bytes.
        buffer
    }

    /// Decodes the canonical state encoding.
    ///
    /// Truncation, trailing bytes, unknown tags, an unsupported descriptor and any state that no
    /// accepted transition could have produced are rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self, SplitDecodeError> {
        let mut reader = Reader::new(bytes);

        // 1 Read and check the schema version.
        let schema_version = reader.u8()?;
        if schema_version != SCHEMA_VERSION {
            return Err(SplitDecodeError::UnknownSchemaVersion {
                expected: SCHEMA_VERSION,
                actual: schema_version,
            });
        }

        // 2 Read the instance presence flag.
        let instance_presence = reader.u8()?;

        // 3 Read the instance block when present.
        let instance = match instance_presence {
            0 => None,
            1 => {
                let descriptor = SplitDescriptor {
                    network_genesis_hash: reader.key()?,
                    template_hash: reader.key()?,
                    owner_key: reader.key()?,
                    bob_key: reader.key()?,
                    carol_key: reader.key()?,
                    fee_key: reader.key()?,
                    bob_weight_bps: reader.u16()?,
                    carol_weight_bps: reader.u16()?,
                };

                // 3.1 Reject an unsupported immutable descriptor.
                descriptor
                    .validate()
                    .map_err(|error| SplitDecodeError::InvalidDescriptor {
                        reason: describe_descriptor_error(&error),
                    })?;

                // 3.1 Read the remaining instance fields in frozen order.
                let contract_id = reader.key()?;
                let gross_sats = reader.u64()?;
                let execution_fee_sats = reader.u64()?;
                let phase_tag = reader.u8()?;
                let phase = Phase::from_tag(phase_tag)
                    .ok_or(SplitDecodeError::UnknownPhaseTag(phase_tag))?;
                let contract_balance_sats = reader.u64()?;
                let bob_shadow_sats = reader.u64()?;
                let carol_shadow_sats = reader.u64()?;
                let instance_sequence = reader.u64()?;

                let instance = SplitInstance {
                    descriptor,
                    contract_id,
                    gross_sats,
                    execution_fee_sats,
                    phase,
                    contract_balance_sats,
                    bob_shadow_sats,
                    carol_shadow_sats,
                    instance_sequence,
                };

                // 3.2 Reject a phase/balance combination no accepted transition can produce.
                instance.check_phase_consistency()?;

                // 3.3 An instantiated vault has necessarily accepted `InstantiateSplit`.
                if instance.instance_sequence == 0 {
                    return Err(SplitDecodeError::InconsistentState {
                        reason: "instantiated instance has a zero instance sequence",
                    });
                }

                Some(instance)
            }
            flag => return Err(SplitDecodeError::UnknownInstancePresenceFlag(flag)),
        };

        // 4 Read the four native balances.
        let ledger = Ledger::new(reader.u64()?, reader.u64()?, reader.u64()?, reader.u64()?);

        // 5 Read the four caller authorization sequences.
        let mut sequences = [0u64; 4];
        for sequence in sequences.iter_mut() {
            *sequence = reader.u64()?;
        }

        // 6 Reject trailing bytes.
        if reader.remaining() != 0 {
            return Err(SplitDecodeError::TrailingBytes {
                decoded: reader.offset(),
                actual: bytes.len(),
            });
        }

        // 7 Return the decoded state.
        Ok(Self {
            instance,
            ledger,
            sequences,
        })
    }

    /// Returns the canonical BIP-340 style tagged digest of this state.
    pub fn digest(&self) -> [u8; 32] {
        self.encode()
            .hash(Some(HashTag::CustomString(STATE_DIGEST_TAG.to_string())))
    }

    /// Returns the native balance of a role.
    pub fn balance_sats(&self, role: Role) -> u64 {
        self.ledger.balance(role)
    }

    /// Returns the last consumed caller authorization sequence of a role.
    pub fn sequence_of(&self, role: Role) -> u64 {
        self.sequences[role.index()]
    }
}

/// Returns a stable description of a descriptor rejection for the decoder.
fn describe_descriptor_error(error: &SplitVaultError) -> &'static str {
    match error {
        SplitVaultError::ZeroParticipantKey { .. } => "descriptor has an all-zero participant key",
        SplitVaultError::DuplicateParticipantKey { .. } => {
            "descriptor has aliased participant keys"
        }
        SplitVaultError::UnsupportedWeights { .. } => "descriptor has unsupported weights",
        _ => "descriptor is not supported",
    }
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
    fn take(&mut self, count: usize) -> Result<&'a [u8], SplitDecodeError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(SplitDecodeError::Truncated {
                offset: self.offset,
                needed: count,
            })?;

        if end > self.bytes.len() {
            return Err(SplitDecodeError::Truncated {
                offset: self.offset,
                needed: count,
            });
        }

        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    /// Reads one byte.
    fn u8(&mut self) -> Result<u8, SplitDecodeError> {
        Ok(self.take(1)?[0])
    }

    /// Reads one little-endian `u16`.
    fn u16(&mut self) -> Result<u16, SplitDecodeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Reads one little-endian `u64`.
    fn u64(&mut self) -> Result<u64, SplitDecodeError> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(array))
    }

    /// Reads one 32-byte key.
    fn key(&mut self) -> Result<[u8; 32], SplitDecodeError> {
        let bytes = self.take(32)?;
        let mut array = [0u8; 32];
        array.copy_from_slice(bytes);
        Ok(array)
    }
}
