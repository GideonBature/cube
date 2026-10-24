//! Executable edges of the splitter's Bitcoin ownership graph.
//!
//! Each module implements one logical transaction role from specification.md section 9.2 with
//! explicit inputs, outputs, values and signer obligations, so that a role can be reviewed and
//! exercised against a node instead of being described in prose.
//!
//! Implemented so far:
//!
//! - `successor_funding`: the `SuccessorFunding` role, which turns a confirmed deposit into the
//!   beneficiary claims.
//!
//! Not implemented: `ExitRequest`, `Assert`, `Take` and `Disprove` (the dispute branch), and the
//! `CooperativeSettle` and `Recovery` edges. `GRAPH-01` therefore stays open; this module reduces it
//! by one edge rather than closing it.

pub mod successor_funding;
