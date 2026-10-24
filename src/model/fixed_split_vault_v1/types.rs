/// The four logical account slots of the bounded pilot profile (specification.md section 12).
///
/// `Owner` is Alice the funding account, `Bob` and `Carol` are the two beneficiaries and `Fee`
/// is the disclosed execution-fee account. The slot order is frozen: it is the canonical order
/// used by the state encoding and by the future circuit's fixed account slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Owner,
    Bob,
    Carol,
    Fee,
}

impl Role {
    /// All roles in canonical slot order.
    pub const ALL: [Role; 4] = [Role::Owner, Role::Bob, Role::Carol, Role::Fee];

    /// Returns the canonical slot index of the role.
    pub fn index(self) -> usize {
        match self {
            Role::Owner => 0,
            Role::Bob => 1,
            Role::Carol => 2,
            Role::Fee => 3,
        }
    }

    /// Returns the role of a canonical slot index.
    pub fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Role::Owner),
            1 => Some(Role::Bob),
            2 => Some(Role::Carol),
            3 => Some(Role::Fee),
            _ => None,
        }
    }

    /// Returns whether the role is one of the two beneficiaries of the split.
    pub fn is_beneficiary(self) -> bool {
        matches!(self, Role::Bob | Role::Carol)
    }
}

/// The logical lifecycle phase of a split instance (specification.md section 3.3).
///
/// The phase tags are frozen because they enter the canonical state encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Instantiated, zero balance, zero allocations, principal not locked.
    Empty,
    /// Funded once: contract balance equals the sum of both shadows.
    Allocated,
    /// Exactly one beneficiary has redeemed its entire shadow allocation.
    PartiallyRedeemed,
    /// Both beneficiaries have redeemed; contract balance and both shadows are zero.
    Closed,
}

impl Phase {
    /// Returns the frozen encoding tag of the phase.
    pub fn tag(self) -> u8 {
        match self {
            Phase::Empty => 0x00,
            Phase::Allocated => 0x01,
            Phase::PartiallyRedeemed => 0x02,
            Phase::Closed => 0x03,
        }
    }

    /// Returns the phase of a frozen encoding tag.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x00 => Some(Phase::Empty),
            0x01 => Some(Phase::Allocated),
            0x02 => Some(Phase::PartiallyRedeemed),
            0x03 => Some(Phase::Closed),
            _ => None,
        }
    }
}

/// The four native account balances of the bounded pilot profile, in satoshis.
///
/// Contract balances and shadow allocations are never stored here. Physical value is
/// `ledger.sum() + contract_balance_sats`; shadows describe obligations against the contract
/// balance and MUST NOT be added again (specification.md section 3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ledger {
    pub owner_sats: u64,
    pub bob_sats: u64,
    pub carol_sats: u64,
    pub fee_sats: u64,
}

impl Ledger {
    /// Constructs a ledger from the four native balances.
    pub fn new(owner_sats: u64, bob_sats: u64, carol_sats: u64, fee_sats: u64) -> Self {
        Self {
            owner_sats,
            bob_sats,
            carol_sats,
            fee_sats,
        }
    }

    /// Returns an empty ledger.
    pub fn zero() -> Self {
        Self::default()
    }

    /// Returns the native balance of a role.
    pub fn balance(self, role: Role) -> u64 {
        match role {
            Role::Owner => self.owner_sats,
            Role::Bob => self.bob_sats,
            Role::Carol => self.carol_sats,
            Role::Fee => self.fee_sats,
        }
    }

    /// Returns a copy with the native balance of a role replaced.
    ///
    /// The caller is responsible for having validated the value; the reference model only ever
    /// calls this with amounts it has already range checked.
    pub fn with_balance(self, role: Role, balance_sats: u64) -> Self {
        match role {
            Role::Owner => Self {
                owner_sats: balance_sats,
                ..self
            },
            Role::Bob => Self {
                bob_sats: balance_sats,
                ..self
            },
            Role::Carol => Self {
                carol_sats: balance_sats,
                ..self
            },
            Role::Fee => Self {
                fee_sats: balance_sats,
                ..self
            },
        }
    }

    /// Returns the sum of all four native balances as a wide integer.
    ///
    /// The addition happens in `u128` so that four individually valid `u64` balances cannot wrap
    /// the conservation check.
    pub fn sum(self) -> u128 {
        (self.owner_sats as u128)
            + (self.bob_sats as u128)
            + (self.carol_sats as u128)
            + (self.fee_sats as u128)
    }
}

/// The basis-point denominator of the fixed split.
pub const BPS_DENOMINATOR: u16 = 10_000;

/// Bob's frozen weight in basis points.
pub const BOB_WEIGHT_BPS: u16 = 7_000;

/// Carol's frozen weight in basis points.
pub const CAROL_WEIGHT_BPS: u16 = 3_000;

/// The minimum claim value accepted by this fixture profile, in satoshis.
///
/// This mirrors `MIN_PAYABLE_ALLOCATION_VALUE` in the CubeVM executor and is a test fixture, not
/// a final dust or exit rule. Specification.md section 12 requires the real limit to be frozen
/// from measurements.
pub const MINIMUM_CLAIM_SATS: u64 = 10;
