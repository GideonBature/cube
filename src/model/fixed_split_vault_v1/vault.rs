use crate::model::fixed_split_vault_v1::amounts::{split_amounts, SplitAmounts};
use crate::model::fixed_split_vault_v1::codec::SplitState;
use crate::model::fixed_split_vault_v1::error::{InvariantViolation, SplitVaultError};
use crate::model::fixed_split_vault_v1::instance::{SplitDescriptor, SplitInstance};
use crate::model::fixed_split_vault_v1::types::{Ledger, Phase, Role};
use crate::transmutative::hash::{Hash, HashTag};
use std::collections::BTreeMap;

/// The BIP-340 style tagged-hash tag of the contract identity derivation.
pub const INSTANCE_ID_TAG: &str = "CubeV1/Instance/v0";

/// The caller authorization of one entry.
///
/// `sequence` is the caller's next authorization sequence. It is consumed exactly once by an
/// accepted operation and never becomes reusable after a rejection, a restart or a replay.
///
/// Signature verification is deliberately outside this model: the reference model checks *which
/// caller* and *which sequence*, and the adapter that turns a real entry into an `Auth` is
/// responsible for proving that the caller authorised this exact payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Auth {
    pub role: Role,
    pub sequence: u64,
}

impl Auth {
    /// Constructs a caller authorization.
    pub fn new(role: Role, sequence: u64) -> Self {
        Self { role, sequence }
    }
}

/// The stable identity and byte digest of one operation.
///
/// Retries reuse both fields. A repeated `id` with the same `payload_digest` is an idempotent
/// replay; a repeated `id` with a different digest is a deterministic conflict
/// (specification.md section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Operation {
    pub id: [u8; 32],
    pub payload_digest: [u8; 32],
}

impl Operation {
    /// Constructs an operation identity.
    pub fn new(id: [u8; 32], payload_digest: [u8; 32]) -> Self {
        Self { id, payload_digest }
    }
}

/// The record of an operation that has already been accepted by this vault.
///
/// The caller and the sequence are stored next to the payload digest so that a retry can be
/// distinguished from a *different* caller reusing a known operation ID. A retry must come from
/// the same role at the same sequence with the same bytes; anything else is a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumedOperation {
    /// The payload digest the ID was first consumed with.
    pub payload_digest: [u8; 32],
    /// The role that consumed the ID.
    pub role: Role,
    /// The caller sequence that consumed the ID.
    pub sequence: u64,
}

/// What an accepted operation did.
///
/// This is the model's transition delta. It exists so the caller can assert on the economic
/// outcome without re-deriving it, and so a later manifest builder can consume the same record
/// instead of recomputing the split a second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    /// `InstantiateSplit` created the empty instance.
    Instantiated { contract_id: [u8; 32] },
    /// `FundSplit` locked principal and created both allocations.
    Funded { amounts: SplitAmounts },
    /// `RedeemShare` converted one shadow allocation into one native entitlement.
    Redeemed {
        role: Role,
        amount_sats: u64,
        phase: Phase,
    },
    /// The operation was a byte-identical retry and changed nothing.
    Replayed { operation_id: [u8; 32] },
}

/// The reference model of the `FixedSplitVaultV1` pilot contract.
///
/// The vault owns the four native account balances, the optional contract instance, the caller
/// authorization sequences and the consumed-operation record.
///
/// Every transition is written as *validate everything, then commit everything*. A rejected
/// operation therefore leaves the accepted state byte-for-byte unchanged, and the test suite
/// asserts that property on the canonical encoding rather than on a field-by-field comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitVault {
    /// The four native account balances.
    pub ledger: Ledger,
    /// The instantiated contract, or `None` before `InstantiateSplit`.
    pub instance: Option<SplitInstance>,
    /// The last consumed caller authorization sequence per canonical role slot.
    pub sequences: [u64; 4],
    /// The consumed operation record: operation ID to the record that consumed it.
    pub operations: BTreeMap<[u8; 32], ConsumedOperation>,
}

impl SplitVault {
    /// Creates a vault over the given native balances with no instance and no consumed operations.
    pub fn new(ledger: Ledger) -> Self {
        Self {
            ledger,
            instance: None,
            sequences: [0u64; 4],
            operations: BTreeMap::<[u8; 32], ConsumedOperation>::new(),
        }
    }

    /// Returns the canonical committed state.
    pub fn state(&self) -> SplitState {
        SplitState {
            instance: self.instance,
            ledger: self.ledger,
            sequences: self.sequences,
        }
    }

    /// Returns the canonical BIP-340 style tagged digest of the committed state.
    pub fn state_digest(&self) -> [u8; 32] {
        self.state().digest()
    }

    /// Returns the physical value of this vault: native balances plus the contract balance.
    ///
    /// Shadow allocations describe obligations *against* the contract balance, so they are not
    /// added here (specification.md section 3.4).
    pub fn physical_value_sats(&self) -> u128 {
        let contract_balance_sats = match &self.instance {
            Some(instance) => instance.contract_balance_sats as u128,
            None => 0,
        };

        self.ledger.sum() + contract_balance_sats
    }

    /// Applies `InstantiateSplit`.
    ///
    /// Creates one empty instance: zero balance, zero allocations, immutable descriptor fixed and
    /// the caller's authorization sequence consumed. It does not lock contract principal.
    pub fn instantiate(
        &mut self,
        descriptor: SplitDescriptor,
        auth: Auth,
        operation: Operation,
    ) -> Result<Transition, SplitVaultError> {
        // 1 Return an idempotent success for a byte-identical retry, or a conflict otherwise.
        if let Some(transition) = self.replay_or_conflict(auth, &operation)? {
            return Ok(transition);
        }

        // 2 Validate the immutable descriptor.
        descriptor.validate()?;

        // 3 Reject the operation when an instance already exists.
        if let Some(instance) = &self.instance {
            return Err(SplitVaultError::InstanceAlreadyInstantiated {
                contract_id: instance.contract_id,
            });
        }

        // 4 Validate the caller authorization.
        self.check_caller(auth, "OWNER", auth.role == Role::Owner)?;

        // 5 Derive the contract identity from the descriptor and the instantiation operation ID.
        let contract_id = derive_contract_id(&descriptor, &operation.id);

        // 6 Commit: create the empty instance, consume the operation and advance the sequence.
        let mut instance = SplitInstance::new_empty(descriptor, contract_id);
        instance.instance_sequence = 1;
        self.instance = Some(instance);
        self.consume(auth, operation);

        // 7 Return the transition.
        Ok(Transition::Instantiated { contract_id })
    }

    /// Applies `FundSplit`.
    ///
    /// Allowed once, only in `EMPTY`, only by the owner. Atomically debits the owner by `G`,
    /// credits the contract by `D = G - E`, credits the fee account by `E`, creates both
    /// beneficiary shadow allocations and moves the instance to `ALLOCATED`.
    pub fn fund(
        &mut self,
        gross_sats: u64,
        execution_fee_sats: u64,
        auth: Auth,
        operation: Operation,
    ) -> Result<Transition, SplitVaultError> {
        // 1 Return an idempotent success for a byte-identical retry, or a conflict otherwise.
        if let Some(transition) = self.replay_or_conflict(auth, &operation)? {
            return Ok(transition);
        }

        // 2 Require an instantiated instance.
        let instance = self
            .instance
            .as_ref()
            .copied()
            .ok_or(SplitVaultError::InstanceNotInstantiated)?;

        // 3 Require the EMPTY phase: funding is allowed exactly once.
        if instance.phase != Phase::Empty {
            return Err(SplitVaultError::WrongPhase {
                required: "EMPTY",
                actual: instance.phase,
            });
        }

        // 4 Validate the caller authorization.
        self.check_caller(auth, "OWNER", auth.role == Role::Owner)?;

        // 5 Validate the amount arithmetic before touching any balance.
        let amounts = split_amounts(gross_sats, execution_fee_sats)?;

        // 6 Validate that the owner actually holds the authorised gross amount.
        let owner_balance_sats = self.ledger.balance(Role::Owner);
        if owner_balance_sats < gross_sats {
            return Err(SplitVaultError::InsufficientOwnerFunds {
                available_sats: owner_balance_sats,
                required_sats: gross_sats,
            });
        }

        // 7 Compute the resulting balances. Every value is checked before the commit below.
        let new_owner_balance_sats = owner_balance_sats - gross_sats;
        let new_fee_balance_sats = self
            .ledger
            .balance(Role::Fee)
            .checked_add(execution_fee_sats)
            .ok_or(SplitVaultError::BalanceOverflow { role: Role::Fee })?;

        // 8 Commit: debit the owner, credit the fee account and allocate inside the contract.
        self.ledger = self
            .ledger
            .with_balance(Role::Owner, new_owner_balance_sats)
            .with_balance(Role::Fee, new_fee_balance_sats);

        let mut funded_instance = instance;
        funded_instance.gross_sats = gross_sats;
        funded_instance.execution_fee_sats = execution_fee_sats;
        funded_instance.phase = Phase::Allocated;
        funded_instance.contract_balance_sats = amounts.distributable_sats;
        funded_instance.bob_shadow_sats = amounts.bob_sats;
        funded_instance.carol_shadow_sats = amounts.carol_sats;
        funded_instance.instance_sequence = instance.instance_sequence + 1;
        self.instance = Some(funded_instance);

        // 9 Consume the operation and advance the caller sequence.
        self.consume(auth, operation);

        // 10 Return the transition.
        Ok(Transition::Funded { amounts })
    }

    /// Applies `RedeemShare`.
    ///
    /// Allowed for Bob or Carol, authenticated by that beneficiary, while at least one shadow
    /// allocation is live. Consumes the caller's entire nonzero shadow allocation, decreases the
    /// contract balance by the same amount and credits one native successor entitlement to the
    /// same beneficiary. It is a change of representation, not an additional credit.
    pub fn redeem(
        &mut self,
        auth: Auth,
        operation: Operation,
    ) -> Result<Transition, SplitVaultError> {
        // 1 Return an idempotent success for a byte-identical retry, or a conflict otherwise.
        if let Some(transition) = self.replay_or_conflict(auth, &operation)? {
            return Ok(transition);
        }

        // 2 Require an instantiated instance.
        let instance = self
            .instance
            .as_ref()
            .copied()
            .ok_or(SplitVaultError::InstanceNotInstantiated)?;

        // 3 Require a phase in which a redemption is still possible.
        match instance.phase {
            Phase::Allocated | Phase::PartiallyRedeemed => {}
            Phase::Empty | Phase::Closed => {
                return Err(SplitVaultError::WrongPhase {
                    required: "ALLOCATED or PARTIALLY_REDEEMED",
                    actual: instance.phase,
                })
            }
        }

        // 4 Validate the caller authorization before disclosing any entitlement.
        self.check_caller(auth, "BOB or CAROL", auth.role.is_beneficiary())?;

        // 5 Require a nonzero shadow allocation for the caller.
        let redeemable_sats = match auth.role {
            Role::Bob => instance.bob_shadow_sats,
            Role::Carol => instance.carol_shadow_sats,
            Role::Owner | Role::Fee => 0,
        };
        if redeemable_sats == 0 {
            return Err(SplitVaultError::NoShadowAllocation { role: auth.role });
        }

        // 6 Compute the resulting balances and phase before the commit.
        let new_contract_balance_sats = instance.contract_balance_sats - redeemable_sats;
        let new_native_balance_sats = self
            .ledger
            .balance(auth.role)
            .checked_add(redeemable_sats)
            .ok_or(SplitVaultError::BalanceOverflow { role: auth.role })?;

        let (new_bob_shadow_sats, new_carol_shadow_sats) = match auth.role {
            Role::Bob => (0u64, instance.carol_shadow_sats),
            Role::Carol => (instance.bob_shadow_sats, 0u64),
            Role::Owner | Role::Fee => (instance.bob_shadow_sats, instance.carol_shadow_sats),
        };

        let new_phase = if new_bob_shadow_sats == 0 && new_carol_shadow_sats == 0 {
            Phase::Closed
        } else {
            Phase::PartiallyRedeemed
        };

        // 8 Commit: move the claim from the shadow representation to the native representation.
        self.ledger = self.ledger.with_balance(auth.role, new_native_balance_sats);

        let mut redeemed_instance = instance;
        redeemed_instance.contract_balance_sats = new_contract_balance_sats;
        redeemed_instance.bob_shadow_sats = new_bob_shadow_sats;
        redeemed_instance.carol_shadow_sats = new_carol_shadow_sats;
        redeemed_instance.phase = new_phase;
        redeemed_instance.instance_sequence = instance.instance_sequence + 1;
        self.instance = Some(redeemed_instance);

        // 9 Consume the operation and advance the caller sequence.
        self.consume(auth, operation);

        // 10 Return the transition.
        Ok(Transition::Redeemed {
            role: auth.role,
            amount_sats: redeemable_sats,
            phase: new_phase,
        })
    }

    /// Returns an idempotent replay outcome, `None` for a fresh operation ID, or a conflict.
    ///
    /// A replay is only accepted when the ID, the payload digest, the caller role and the caller
    /// sequence all match the record created by the first acceptance. Anything else is a
    /// deterministic conflict, including a different caller reusing a known operation ID.
    fn replay_or_conflict(
        &self,
        auth: Auth,
        operation: &Operation,
    ) -> Result<Option<Transition>, SplitVaultError> {
        match self.operations.get(&operation.id) {
            // The same ID, bytes, caller and sequence: an idempotent retry.
            Some(consumed)
                if consumed.payload_digest == operation.payload_digest
                    && consumed.role == auth.role
                    && consumed.sequence == auth.sequence =>
            {
                Ok(Some(Transition::Replayed {
                    operation_id: operation.id,
                }))
            }
            // Anything else under a known ID: a deterministic conflict.
            Some(_) => Err(SplitVaultError::OperationIdConflict {
                operation_id: operation.id,
            }),
            // A fresh operation.
            None => Ok(None),
        }
    }

    /// Validates the caller authorization sequence for an operation.
    ///
    /// `required` is only the human-readable name of the permitted roles that ends up in the
    /// error; `authorized` is the actual policy decision, passed explicitly so that this helper
    /// cannot drift from the caller's intent.
    fn check_caller(
        &self,
        auth: Auth,
        required: &'static str,
        authorized: bool,
    ) -> Result<(), SplitVaultError> {
        // 1 Reject an unauthorized role.
        if !authorized {
            return Err(SplitVaultError::UnauthorizedCaller {
                required,
                actual: auth.role,
            });
        }

        // 2 Require the next sequence value.
        let last_consumed = self.sequences[auth.role.index()];
        let expected = last_consumed
            .checked_add(1)
            .ok_or(SplitVaultError::CallerSequenceExhausted { role: auth.role })?;
        if auth.sequence != expected {
            return Err(SplitVaultError::UnexpectedCallerSequence {
                expected,
                actual: auth.sequence,
            });
        }

        // 3 Return Ok.
        Ok(())
    }

    /// Records a consumed operation and advances the caller authorization sequence.
    fn consume(&mut self, auth: Auth, operation: Operation) {
        self.operations.insert(
            operation.id,
            ConsumedOperation {
                payload_digest: operation.payload_digest,
                role: auth.role,
                sequence: auth.sequence,
            },
        );
        self.sequences[auth.role.index()] = auth.sequence;
    }

    /// Returns the next unused operation ID, for tests and fixtures.
    ///
    /// The value is derived deterministically from a caller-chosen seed so that fixtures are
    /// reproducible without a random number generator.
    pub fn next_operation_id(seed: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        for (index, byte) in id.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        id
    }

    /// Returns the payload digest of a canonical byte string, for tests and fixtures.
    pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
        payload.hash(Some(HashTag::CustomString("CubeV1/Payload/v0".to_string())))
    }

    /// Checks the state invariants that the model must preserve.
    ///
    /// A violation is a model bug, not a rejection of a user entry, so this returns its own error
    /// type rather than a `SplitVaultError`.
    pub fn check_invariants(&self) -> Result<(), InvariantViolation> {
        // 1 Without an instance there is no contract balance and no obligation.
        let Some(instance) = &self.instance else {
            return Ok(());
        };

        // 2 INV-02: the sum of remaining shadows never exceeds the contract balance.
        let shadows_sats = instance.shadows_sum_sats();
        let contract_balance_sats = instance.contract_balance_sats as u128;
        if shadows_sats > contract_balance_sats {
            return Err(InvariantViolation::ShadowExceedsContractBalance {
                shadows_sats: instance
                    .bob_shadow_sats
                    .saturating_add(instance.carol_shadow_sats),
                contract_balance_sats: instance.contract_balance_sats,
            });
        }

        // 3 The stored balances agree with the stored phase.
        let mismatch = || InvariantViolation::PhaseBalanceMismatch {
            phase: instance.phase,
            contract_balance_sats: instance.contract_balance_sats,
            bob_shadow_sats: instance.bob_shadow_sats,
            carol_shadow_sats: instance.carol_shadow_sats,
        };

        match instance.phase {
            // 3.a EMPTY: instantiated but nothing allocated and nothing funded.
            Phase::Empty => {
                if instance.contract_balance_sats != 0
                    || instance.bob_shadow_sats != 0
                    || instance.carol_shadow_sats != 0
                    || instance.gross_sats != 0
                    || instance.execution_fee_sats != 0
                {
                    return Err(mismatch());
                }
            }
            // 3.b ALLOCATED: both allocations live and exactly backed by the contract balance.
            Phase::Allocated => {
                if instance.bob_shadow_sats == 0
                    || instance.carol_shadow_sats == 0
                    || shadows_sats != contract_balance_sats
                {
                    return Err(mismatch());
                }
            }
            // 3.c PARTIALLY_REDEEMED: exactly one allocation consumed, the rest still backed.
            Phase::PartiallyRedeemed => {
                let exactly_one_zero =
                    (instance.bob_shadow_sats == 0) != (instance.carol_shadow_sats == 0);
                if !exactly_one_zero || shadows_sats != contract_balance_sats {
                    return Err(mismatch());
                }
            }
            // 3.d CLOSED: nothing remains inside the vault.
            Phase::Closed => {
                if instance.bob_shadow_sats != 0
                    || instance.carol_shadow_sats != 0
                    || instance.contract_balance_sats != 0
                {
                    return Err(mismatch());
                }
            }
        }

        Ok(())
    }
}

/// Derives the contract identity of one instance.
///
/// `contract_id = TaggedHash("CubeV1/Instance/v0", canonical_descriptor || operation_id)`.
///
/// The identity deliberately excludes `G` and `E`: `InstantiateSplit` fixes the instance before
/// any principal is authorised, so `FundSplit` cannot change the contract's identity.
pub fn derive_contract_id(descriptor: &SplitDescriptor, operation_id: &[u8; 32]) -> [u8; 32] {
    // 1 Encode the canonical descriptor.
    let mut preimage = descriptor.encode();

    // 2 Bind the unique instantiation operation ID.
    preimage.extend(operation_id);

    // 3 Hash with the instance tag.
    preimage.hash(Some(HashTag::CustomString(INSTANCE_ID_TAG.to_string())))
}
