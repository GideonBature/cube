//! The beneficiary claim output.
//!
//! A claim output is a taproot output with **no key path**: its internal key is the nothing-up-my-
//! sleeve point, so the only way to spend it is the single tapscript leaf. That leaf carries two
//! constants:
//!
//! ```text
//! <32-byte statement digest> OP_DROP <32-byte beneficiary key> OP_CHECKSIG
//! ```
//!
//! The consequence a reviewer should check: the statement digest is committed structurally, not by
//! convention. A claim output funded with digest `D` can only be spent by a witness that reveals a
//! script containing `D`, and only the named beneficiary can produce that witness. When the claim
//! is spent, the script travels in the witness, so any third party can see which statement the
//! claim was bound to.
//!
//! What this does **not** provide:
//!
//! - A digest is not the manifest. Reconstructing the manifest requires the recovery package; a
//!   commitment is not data availability (specification.md section 10).
//! - Nothing here proves the transition that `D` commits to actually happened. That is the
//!   verifier's job.
//! - The beneficiary key is a single key. There is no delay branch, no revocation and no
//!   third-party recovery path on the claim output yet.

use crate::constructive::taproot::{TapLeaf, TapRoot};
use crate::transmutative::hash::{Hash, HashTag};

/// The length of a claim script, in bytes.
pub const CLAIM_SCRIPT_LEN: usize = 68;

/// The opcode that pushes the statement digest.
const OP_PUSH_32: u8 = 0x20;

/// The opcode that discards the pushed digest.
const OP_DROP: u8 = 0x75;

/// The opcode that checks the beneficiary signature.
const OP_CHECKSIG: u8 = 0xac;

/// Returns the claim tapscript for a statement digest and a beneficiary key.
///
/// Layout, frozen:
///
/// ```text
/// 0x20 <digest:32> 0x75 0x20 <beneficiary:32> 0xac
/// ```
pub fn claim_script(statement_digest: [u8; 32], beneficiary_key: [u8; 32]) -> Vec<u8> {
    let mut script = Vec::<u8>::with_capacity(CLAIM_SCRIPT_LEN);
    script.push(OP_PUSH_32);
    script.extend(statement_digest);
    script.push(OP_DROP);
    script.push(OP_PUSH_32);
    script.extend(beneficiary_key);
    script.push(OP_CHECKSIG);
    script
}

/// Returns the claim taproot: one script-path leaf, and no key path.
pub fn claim_taproot(statement_digest: [u8; 32], beneficiary_key: [u8; 32]) -> TapRoot {
    let leaf = TapLeaf::new(claim_script(statement_digest, beneficiary_key));
    TapRoot::script_path_only_single(leaf)
}

/// Returns the claim scriptpubkey, or `None` if the tweak degenerates.
pub fn claim_scriptpubkey(
    statement_digest: [u8; 32],
    beneficiary_key: [u8; 32],
) -> Option<Vec<u8>> {
    claim_taproot(statement_digest, beneficiary_key).spk()
}

/// Returns the control block a claim spend must carry.
pub fn claim_control_block(
    statement_digest: [u8; 32],
    beneficiary_key: [u8; 32],
) -> Option<Vec<u8>> {
    claim_taproot(statement_digest, beneficiary_key)
        .control_block(0)
        .map(|control_block| control_block.to_vec())
}

/// Parses a claim script back into its digest and beneficiary key.
///
/// Used to check what a witness actually revealed. Returns `None` for any script that is not
/// exactly a claim script, so a spend that reveals a different script cannot be mistaken for one
/// that commits to the expected statement.
pub fn parse_claim_script(script: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    // 1 Reject a script that is not exactly the frozen layout.
    if script.len() != CLAIM_SCRIPT_LEN {
        return None;
    }
    if script[0] != OP_PUSH_32 || script[33] != OP_DROP || script[34] != OP_PUSH_32 {
        return None;
    }
    if script[CLAIM_SCRIPT_LEN - 1] != OP_CHECKSIG {
        return None;
    }

    // 2 Extract the two constants.
    let mut statement_digest = [0u8; 32];
    statement_digest.copy_from_slice(&script[1..33]);

    let mut beneficiary_key = [0u8; 32];
    beneficiary_key.copy_from_slice(&script[35..67]);

    Some((statement_digest, beneficiary_key))
}

/// Returns the commitment an `OP_RETURN` output must carry for a statement digest.
///
/// Layout, frozen (39 bytes): `OP_RETURN` `0x04` `CBV1` `0x20` `<digest:32>`.
///
/// The prefix distinguishes a Cube statement commitment from arbitrary `OP_RETURN` traffic on the
/// same network. It is a convention for observers, not a consensus rule.
pub fn statement_op_return_script(statement_digest: [u8; 32]) -> Vec<u8> {
    // 1 `OP_RETURN`.
    let mut script = Vec::<u8>::with_capacity(4 + 32);
    script.push(0x6a);

    // 2 A four-byte prefix so the output is identifiable as a Cube commitment.
    script.push(0x04);
    script.extend(b"CBV1");

    // 3 The statement digest.
    script.push(OP_PUSH_32);
    script.extend(statement_digest);

    script
}

/// Returns the digest committed by an `OP_RETURN` claim-commitment script.
pub fn parse_statement_op_return_script(script: &[u8]) -> Option<[u8; 32]> {
    if script.len() != 39 {
        return None;
    }
    if script[0] != 0x6a || script[1] != 0x04 || &script[2..6] != b"CBV1" {
        return None;
    }
    if script[6] != OP_PUSH_32 {
        return None;
    }

    let mut statement_digest = [0u8; 32];
    statement_digest.copy_from_slice(&script[7..39]);
    Some(statement_digest)
}

/// Returns the tagged digest of a claim script, for logs and fixture comparisons.
pub fn claim_script_digest(script: &[u8]) -> [u8; 32] {
    script.hash(Some(HashTag::CustomString(
        "CubeV1/ClaimScript/v0".to_string(),
    )))
}
