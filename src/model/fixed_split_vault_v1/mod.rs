//! The bounded `FixedSplitVaultV1` pilot contract (specification.md section 3).
//!
//! One instance fixes two beneficiary weights (7000 / 3000 basis points), one owner and one
//! disclosed execution-fee account. It moves through four phases:
//!
//! ```text
//! EMPTY --FundSplit--> ALLOCATED --RedeemShare(Bob|Carol)--> PARTIALLY_REDEEMED --> CLOSED
//! ```
//!
//! `InstantiateSplit` creates the empty instance and locks the immutable descriptor. It does not
//! lock principal. `FundSplit` is allowed once and atomically debits the owner, credits the
//! contract, credits the fee account and creates both beneficiary shadow allocations.
//! `RedeemShare` converts one shadow allocation into one native successor entitlement owned by
//! the same beneficiary.
//!
//! All amounts are exact `u64` satoshis. There is no floating point and no fractional accounting:
//! Bob receives `floor(D * 7000 / 10000)` and Carol receives the integer remainder `D - Bob`.
//!
//! Every entry is bound to a caller, a caller authorization sequence and a stable operation ID.
//! A retry with the same operation ID, payload, caller and sequence is an idempotent replay;
//! any other reuse of a known ID is a deterministic conflict. A rejected entry leaves the state
//! byte-for-byte unchanged.

pub mod amounts;
pub mod codec;
pub mod derive;
pub mod error;
pub mod instance;
pub mod manifest;
pub mod types;
pub mod vault;

pub use amounts::{split_amounts, SplitAmounts};
pub use codec::SplitState;
pub use error::{InvariantViolation, SplitDecodeError, SplitVaultError};
pub use instance::{SplitDescriptor, SplitInstance};
pub use derive::{derive_manifest, DeriveError, ManifestContext};
pub use manifest::{
    Anchor, ManifestError, Payout, PayoutKind, ReleaseProfile, TransitionManifest,
    MANIFEST_SCHEMA_VERSION, MAX_ANCHORS, MAX_PAYOUTS, STATEMENT_DIGEST_TAG,
};
pub use types::{Ledger, Phase, Role};
pub use vault::{derive_contract_id, Auth, ConsumedOperation, Operation, SplitVault, Transition};
