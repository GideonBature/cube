//! Allowlisted contract templates.
//!
//! A template in this module is a concrete CubeVM `Program` whose opcode sequence, argument layout
//! and compiled hash are pinned. Deploying anything else is not covered by a template hash and
//! must not be treated as an allowlisted contract.

pub mod fixed_split_vault_v1;
