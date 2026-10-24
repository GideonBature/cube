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
//! - `claim_recovery`: the `Recovery` role, which spends one claim from its recovery package without
//!   the Engine.
//! - `exit_request`: the `ExitRequest` role, an on-chain notice that binds a claim, a deadline and a
//!   data-disclosure commitment.
//! - `assertion`: the `Assert`, `Take` and `Disprove` edges. `Assert` binds the published proof
//!   input to the claim through the beneficiary's signature over a digest that commits the
//!   statement, table, instance, disclosure secret and input bytes; `Take` is a timelocked
//!   operator settlement and `Disprove` is the secret-based dispute. The construction and its
//!   remaining gap are specified in `docs/bind_01.md`.
//!
//! Not implemented: the `CooperativeSettle` edge. `Assert`, `Take` and `Disprove` exist as a
//! mechanism but are not yet attached to the frozen v1 claim: a claim that carries the assertion
//! leaf needs a recovery-package v2, which is the next step rather than a silent script change.
//! `GRAPH-01` therefore stays open.
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

pub mod assertion;
pub mod claim_recovery;
pub mod exit_request;
pub mod successor_funding;
