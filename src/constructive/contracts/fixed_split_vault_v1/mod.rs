//! The `FixedSplitVaultV1` contract template.
//!
//! This module owns the executable program only: the exact opcode sequence, the argument layout
//! and the compiled hash. The lifecycle semantics it implements are specified in
//! specification.md section 3 and mirrored by the independent reference model in
//! `crate::model::fixed_split_vault_v1`, which is the differential oracle for these tests.

pub mod template;

pub use template::{
    template, template_bytes, template_hash, FUND_SPLIT_METHOD_NAME, PROGRAM_NAME,
    REDEEM_SHARE_METHOD_NAME,
};
