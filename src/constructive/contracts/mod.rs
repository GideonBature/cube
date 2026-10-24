//! Allowlisted contract templates.
//!
//! A template in this module is a concrete CubeVM `Program` whose opcode sequence, argument layout
//! and compiled hash are pinned. Deploying anything else is not covered by a template hash and
//! must not be treated as an allowlisted contract.
//!
//! # The allowlist
//!
//! [`is_allowlisted_template`] is the single place that decides whether a compiled contract is
//! reviewed. It is deliberately a static list and not configuration: adding a contract requires a
//! code change, a review and a new entry, so a runtime mismatch cannot silently widen the set of
//! contracts the engine will execute.
//!
//! The gate sits on the `Deploy` entry, because a deploy is the point at which a program enters the
//! registry. The call path stays generic and does not re-check the allowlist, so a contract that
//! was already registered before the policy is a migration question, not something a call can
//! re-decide.

pub mod fixed_split_vault_v1;

/// Returns whether `template_hash` is a template this build treats as reviewed.
///
/// The hash is the compiled executable's identity, so any change to an opcode, an argument type or
/// a method name changes it and drops the contract off the list until it is reviewed again.
pub fn is_allowlisted_template(template_hash: [u8; 32]) -> bool {
    template_hash == fixed_split_vault_v1::template_hash()
}
