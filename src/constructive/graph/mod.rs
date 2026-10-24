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
//!
//! # Authorization
//!
//! These edges do not verify BIP-340 inside the proof relation. They rely on the signatures Bitcoin
//! itself checks on each edge, which specification.md section 8.2 accepts as an alternative when it
//! is documented and demonstrated rather than assumed:
//!
//! - `SuccessorFunding` spends the deposit key path, a MuSig2 aggregate of the participant and the
//!   Engine. The sighash covers every output, including each claim and the `OP_RETURN` statement
//!   commitment, so no committed byte can change after signing. `tests/liftv2_regtest.rs` shows
//!   Bitcoin Core accepting the honest spend and rejecting the same spend with one digest byte
//!   changed.
//! - A claim output has no key path. Its single tapscript leaf requires the named beneficiary's
//!   signature, and spending it reveals the committed digest in the witness.
//! - A Cube entry's own authorization is BLS (`Call::bls_verify`) on the engine path. It is neither
//!   BIP-340 nor checked by the relation.
//!
//! What a signature establishes is **who authorised these exact bytes**. It establishes nothing
//! about whether those bytes are a correct transition: the participant and the Engine can co-sign a
//! successor that pays the wrong amounts, and the circuit is what rejects that. Authorization and
//! correctness are separate obligations, and neither substitutes for the other.
//!
//! In-circuit BIP-340 remains unimplemented. No reviewed secp256k1-and-square-root gadget is
//! available at the pinned arkworks version, and non-native field arithmetic for it is a project of
//! its own with its own review. Until such a gadget exists, a relation for this profile has to be
//! paired with a graph whose signatures cover the statement, which is what these edges provide.

pub mod successor_funding;
