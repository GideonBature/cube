use crate::model::fixed_split_vault_v1::error::SplitVaultError;
use crate::model::fixed_split_vault_v1::types::{
    Phase, Role, BOB_WEIGHT_BPS, CAROL_WEIGHT_BPS, MINIMUM_CLAIM_SATS,
};

/// The immutable parameters of one split instance (specification.md section 3.3).
///
/// The descriptor is fixed by `InstantiateSplit` and cannot change afterwards: `FundSplit` and
/// `RedeemShare` never write to it. It deliberately excludes the gross amount and the execution
/// fee, because those are authorised later by `FundSplit` and therefore cannot participate in the
/// contract identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitDescriptor {
    /// The genesis hash of the target Bitcoin network. Binds the instance to one network.
    pub network_genesis_hash: [u8; 32],
    /// The hash of the compiled allowlisted template this instance executes.
    pub template_hash: [u8; 32],
    /// Alice, the funding account.
    pub owner_key: [u8; 32],
    /// Bob, the first beneficiary.
    pub bob_key: [u8; 32],
    /// Carol, the second beneficiary.
    pub carol_key: [u8; 32],
    /// F, the disclosed execution-fee account.
    pub fee_key: [u8; 32],
    /// Bob's weight in basis points. Frozen at 7000 for this profile.
    pub bob_weight_bps: u16,
    /// Carol's weight in basis points. Frozen at 3000 for this profile.
    pub carol_weight_bps: u16,
}

impl SplitDescriptor {
    /// Constructs a descriptor with the frozen 70/30 weights.
    ///
    /// The descriptor is not validated here; `validate` is called by the accepted transition so
    /// that a rejected descriptor never reaches the vault.
    pub fn new(
        network_genesis_hash: [u8; 32],
        template_hash: [u8; 32],
        owner_key: [u8; 32],
        bob_key: [u8; 32],
        carol_key: [u8; 32],
        fee_key: [u8; 32],
    ) -> Self {
        Self {
            network_genesis_hash,
            template_hash,
            owner_key,
            bob_key,
            carol_key,
            fee_key,
            bob_weight_bps: BOB_WEIGHT_BPS,
            carol_weight_bps: CAROL_WEIGHT_BPS,
        }
    }

    /// Returns the key of a participant role.
    pub fn key(&self, role: Role) -> [u8; 32] {
        match role {
            Role::Owner => self.owner_key,
            Role::Bob => self.bob_key,
            Role::Carol => self.carol_key,
            Role::Fee => self.fee_key,
        }
    }

    /// Validates the immutable parameters.
    ///
    /// Rejections are checked in this frozen order:
    ///
    /// 1. a participant key is all zero, in role order
    /// 2. two participant keys are equal, in role-pair order
    /// 3. the weights are not the frozen 7000 / 3000 pair
    pub fn validate(&self) -> Result<(), SplitVaultError> {
        // 1 Reject the all-zero key, in canonical role order.
        for role in Role::ALL {
            if self.key(role) == [0u8; 32] {
                return Err(SplitVaultError::ZeroParticipantKey { role });
            }
        }

        // 2 Reject aliased participant keys. The initial profile requires distinct keys.
        for (first_index, first) in Role::ALL.iter().enumerate() {
            for second in Role::ALL.iter().skip(first_index + 1) {
                if self.key(*first) == self.key(*second) {
                    return Err(SplitVaultError::DuplicateParticipantKey {
                        first: *first,
                        second: *second,
                    });
                }
            }
        }

        // 3 Reject any weight pair other than the frozen split.
        if self.bob_weight_bps != BOB_WEIGHT_BPS || self.carol_weight_bps != CAROL_WEIGHT_BPS {
            return Err(SplitVaultError::UnsupportedWeights {
                bob_weight_bps: self.bob_weight_bps,
                carol_weight_bps: self.carol_weight_bps,
            });
        }

        // 4 Return Ok.
        Ok(())
    }

    /// Appends the canonical descriptor encoding to a byte buffer.
    ///
    /// Layout (frozen):
    ///
    /// ```text
    /// network_genesis_hash[32] | template_hash[32] | owner[32] | bob[32] | carol[32] | fee[32]
    ///   | bob_weight_bps u16 LE | carol_weight_bps u16 LE
    /// ```
    pub fn encode_into(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.network_genesis_hash);
        buffer.extend(self.template_hash);
        buffer.extend(self.owner_key);
        buffer.extend(self.bob_key);
        buffer.extend(self.carol_key);
        buffer.extend(self.fee_key);
        buffer.extend(self.bob_weight_bps.to_le_bytes());
        buffer.extend(self.carol_weight_bps.to_le_bytes());
    }

    /// Returns the canonical descriptor encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::<u8>::new();
        self.encode_into(&mut buffer);
        buffer
    }
}

/// One instantiated split vault and everything that changes while it is live.
///
/// `descriptor` is immutable; every other field is written only by an accepted transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitInstance {
    /// The immutable parameters fixed by `InstantiateSplit`.
    pub descriptor: SplitDescriptor,
    /// The derived contract identity: `TaggedHash("CubeV1/Instance/v0", descriptor || op_id)`.
    pub contract_id: [u8; 32],
    /// The gross funding amount authorised by `FundSplit`. Zero while `Empty`.
    pub gross_sats: u64,
    /// The disclosed execution fee authorised by `FundSplit`. Zero while `Empty`.
    pub execution_fee_sats: u64,
    /// The logical lifecycle phase.
    pub phase: Phase,
    /// The contract balance backing the remaining shadows, in satoshis.
    pub contract_balance_sats: u64,
    /// Bob's remaining shadow allocation in satoshis.
    pub bob_shadow_sats: u64,
    /// Carol's remaining shadow allocation in satoshis.
    pub carol_shadow_sats: u64,
    /// The number of accepted operations applied to this instance, starting at 1.
    pub instance_sequence: u64,
}

impl SplitInstance {
    /// Creates an empty instance: zero principal, zero allocations, zero sequence.
    pub fn new_empty(descriptor: SplitDescriptor, contract_id: [u8; 32]) -> Self {
        Self {
            descriptor,
            contract_id,
            gross_sats: 0,
            execution_fee_sats: 0,
            phase: Phase::Empty,
            contract_balance_sats: 0,
            bob_shadow_sats: 0,
            carol_shadow_sats: 0,
            instance_sequence: 0,
        }
    }

    /// Returns the remaining shadow allocation of a beneficiary role.
    ///
    /// Returns `None` for `Owner` and `Fee`: neither holds a shadow allocation in this profile.
    pub fn shadow_sats(&self, role: Role) -> Option<u64> {
        match role {
            Role::Bob => Some(self.bob_shadow_sats),
            Role::Carol => Some(self.carol_shadow_sats),
            Role::Owner | Role::Fee => None,
        }
    }

    /// Returns the sum of both remaining shadows as a wide integer.
    pub fn shadows_sum_sats(&self) -> u128 {
        (self.bob_shadow_sats as u128) + (self.carol_shadow_sats as u128)
    }

    /// Validates that the phase and the balances describe one reachable state.
    ///
    /// This is used by the decoder: a byte string that decodes to a state no accepted transition
    /// could have produced is rejected instead of being normalised into one.
    pub fn check_phase_consistency(
        &self,
    ) -> Result<(), crate::model::fixed_split_vault_v1::error::SplitDecodeError> {
        use crate::model::fixed_split_vault_v1::error::SplitDecodeError;

        match self.phase {
            // EMPTY: instantiated but never funded.
            Phase::Empty => {
                if self.gross_sats != 0
                    || self.execution_fee_sats != 0
                    || self.contract_balance_sats != 0
                    || self.bob_shadow_sats != 0
                    || self.carol_shadow_sats != 0
                {
                    return Err(SplitDecodeError::InconsistentState {
                        reason: "EMPTY instance carries a nonzero amount",
                    });
                }
            }
            // ALLOCATED: both allocations live and fully backed by the contract balance.
            Phase::Allocated => {
                if self.bob_shadow_sats == 0 || self.carol_shadow_sats == 0 {
                    return Err(SplitDecodeError::InconsistentState {
                        reason: "ALLOCATED instance has a zero beneficiary allocation",
                    });
                }
                if self.bob_shadow_sats < MINIMUM_CLAIM_SATS
                    || self.carol_shadow_sats < MINIMUM_CLAIM_SATS
                {
                    return Err(SplitDecodeError::InconsistentState {
                        reason: "ALLOCATED instance has a below-minimum allocation",
                    });
                }
                if self.shadows_sum_sats() != (self.contract_balance_sats as u128) {
                    return Err(SplitDecodeError::InconsistentState {
                        reason: "ALLOCATED instance shadows do not equal the contract balance",
                    });
                }
            }
            // PARTIALLY_REDEEMED: exactly one allocation was consumed.
            Phase::PartiallyRedeemed => {
                let bob_zero = self.bob_shadow_sats == 0;
                let carol_zero = self.carol_shadow_sats == 0;
                if bob_zero == carol_zero {
                    return Err(SplitDecodeError::InconsistentState {
                        reason: "PARTIALLY_REDEEMED instance must have exactly one zero allocation",
                    });
                }
                if self.shadows_sum_sats() != (self.contract_balance_sats as u128) {
                    return Err(SplitDecodeError::InconsistentState {
                        reason: "PARTIALLY_REDEEMED shadows do not equal the contract balance",
                    });
                }
            }
            // CLOSED: nothing left inside the vault.
            Phase::Closed => {
                if self.contract_balance_sats != 0
                    || self.bob_shadow_sats != 0
                    || self.carol_shadow_sats != 0
                {
                    return Err(SplitDecodeError::InconsistentState {
                        reason: "CLOSED instance carries a nonzero balance or allocation",
                    });
                }
            }
        }

        Ok(())
    }

    /// Appends the canonical instance encoding to a byte buffer.
    ///
    /// Layout (frozen, 277 bytes):
    ///
    /// ```text
    /// descriptor (196 bytes) | contract_id[32] | gross_sats u64 | execution_fee_sats u64
    ///   | phase u8 | contract_balance_sats u64 | bob_shadow_sats u64 | carol_shadow_sats u64
    ///   | instance_sequence u64
    /// ```
    pub fn encode_into(&self, buffer: &mut Vec<u8>) {
        self.descriptor.encode_into(buffer);
        buffer.extend(self.contract_id);
        buffer.extend(self.gross_sats.to_le_bytes());
        buffer.extend(self.execution_fee_sats.to_le_bytes());
        buffer.push(self.phase.tag());
        buffer.extend(self.contract_balance_sats.to_le_bytes());
        buffer.extend(self.bob_shadow_sats.to_le_bytes());
        buffer.extend(self.carol_shadow_sats.to_le_bytes());
        buffer.extend(self.instance_sequence.to_le_bytes());
    }
}
