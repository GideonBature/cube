//! The `FixedSplitVaultV1` contract template.
//!
//! This module owns the executable program only: the exact opcode sequence, the argument layout
//! and the compiled hash. The lifecycle semantics it implements are specified in
//! specification.md section 3 and mirrored by the independent reference model in
//! `crate::model::fixed_split_vault_v1`, which is the differential oracle for these tests.

pub mod claim;
pub mod recovery_package;
pub mod template;

pub use claim::{
    assertion_claim_control_block, assertion_claim_script, assertion_claim_scriptpubkey,
    assertion_claim_taproot, claim_control_block, claim_script, claim_scriptpubkey, claim_taproot,
    parse_assertion_claim_script, parse_claim_script, parse_statement_op_return_script,
    statement_op_return_script, ASSERTION_CLAIM_SCRIPT_LEN, CLAIM_ASSERTION_LEAF_INDEX,
    CLAIM_RECOVERY_LEAF_INDEX, CLAIM_SCRIPT_LEN,
};
pub use recovery_package::{
    ClaimRecoveryPackage, DischargeState, PackageError, PACKAGE_DIGEST_TAG, PACKAGE_SCHEMA_VERSION,
    PACKAGE_SCHEMA_VERSION_V2,
};
pub use template::{
    template, template_bytes, template_hash, FUND_SPLIT_METHOD_NAME, PROGRAM_NAME,
    REDEEM_SHARE_METHOD_NAME,
};
