use crate::model::fixed_split_vault_v1::types::{Phase, Role};

/// Deterministic rejection reasons of the `FixedSplitVaultV1` reference model.
///
/// Every variant is a pure function of the submitted entry and the accepted state. No variant
/// depends on wall-clock time, a database timestamp or an Engine-local counter, so two
/// implementations can be compared on the returned error as well as on the resulting state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitVaultError {
    // Descriptor validation.
    /// A participant key is the all-zero byte string.
    ZeroParticipantKey { role: Role },
    /// Two participant roles share one key. The initial profile requires distinct keys.
    DuplicateParticipantKey { first: Role, second: Role },
    /// The weights are not the frozen 7000 / 3000 pair.
    UnsupportedWeights {
        bob_weight_bps: u16,
        carol_weight_bps: u16,
    },

    // Amount arithmetic.
    /// The gross funding amount is zero.
    GrossAmountIsZero,
    /// The execution fee is not strictly below the gross funding amount.
    ExecutionFeeNotBelowGross {
        gross_sats: u64,
        execution_fee_sats: u64,
    },
    /// One of the two beneficiary allocations is zero.
    ZeroBeneficiaryAllocation { bob_sats: u64, carol_sats: u64 },
    /// One of the two beneficiary allocations is below the profile minimum.
    BelowMinimumClaim {
        bob_sats: u64,
        carol_sats: u64,
        minimum_sats: u64,
    },
    /// A computed allocation does not fit the `u64` satoshi range.
    ///
    /// Unreachable for any real Bitcoin amount, but the conversion is checked so that the range
    /// claim is enforced rather than assumed.
    AllocationOverflow { allocation_wide: u128 },

    // Lifecycle.
    /// An operation requiring an instance was submitted before `InstantiateSplit`.
    InstanceNotInstantiated,
    /// `InstantiateSplit` was submitted for an instance that already exists.
    InstanceAlreadyInstantiated { contract_id: [u8; 32] },
    /// The instance is in a phase that does not permit this operation.
    WrongPhase {
        required: &'static str,
        actual: Phase,
    },
    /// The calling role is not permitted for this operation.
    UnauthorizedCaller {
        required: &'static str,
        actual: Role,
    },

    // Authorization.
    /// The caller authorization sequence is not the next expected value.
    UnexpectedCallerSequence { expected: u64, actual: u64 },
    /// The caller authorization sequence cannot be advanced without wrapping.
    CallerSequenceExhausted { role: Role },
    /// The same operation ID was reused with different bytes.
    OperationIdConflict { operation_id: [u8; 32] },

    // Accounting.
    /// The owner does not hold enough eligible native funds for the authorised gross amount.
    InsufficientOwnerFunds {
        available_sats: u64,
        required_sats: u64,
    },
    /// The caller holds no nonzero shadow allocation to redeem.
    NoShadowAllocation { role: Role },
    /// A resulting native balance does not fit the `u64` satoshi range.
    ///
    /// Unreachable for any real Bitcoin amount, but the credit is checked so that the range claim
    /// is enforced rather than assumed.
    BalanceOverflow { role: Role },

    // Canonical encoding.
    /// The canonical state encoding could not be decoded.
    Decode(SplitDecodeError),
}

/// Deterministic rejection reasons of the canonical state decoder.
///
/// Alternate encodings, trailing bytes and states that could never have been produced by an
/// accepted transition are all rejected here rather than silently normalised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitDecodeError {
    /// The byte string ended before the field at `offset` could be read.
    Truncated { offset: usize, needed: usize },
    /// The byte string continued after the canonical state was complete.
    TrailingBytes { decoded: usize, actual: usize },
    /// The schema version byte is not the frozen version.
    UnknownSchemaVersion { expected: u8, actual: u8 },
    /// The instance presence flag is neither zero nor one.
    UnknownInstancePresenceFlag(u8),
    /// The phase tag is not a frozen phase.
    UnknownPhaseTag(u8),
    /// The decoded descriptor is not a supported immutable descriptor.
    InvalidDescriptor { reason: &'static str },
    /// The decoded balances contradict the decoded phase.
    InconsistentState { reason: &'static str },
}

/// Violations of the state invariants that the reference model must preserve.
///
/// These are checked by `SplitVault::check_invariants` and are asserted after every accepted
/// transition in the test suite. They are not part of the accepted error surface: a violation is
/// a bug in the model, not a rejection of a user entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantViolation {
    /// INV-02: the sum of remaining shadows exceeds the contract balance.
    ShadowExceedsContractBalance {
        shadows_sats: u64,
        contract_balance_sats: u64,
    },
    /// The stored balances contradict the stored phase.
    PhaseBalanceMismatch {
        phase: Phase,
        contract_balance_sats: u64,
        bob_shadow_sats: u64,
        carol_shadow_sats: u64,
    },
}
