//! Tests for the beneficiary claim output.
//!
//! These are offline checks of the claim construct: the script layout, the fact that the statement
//! digest and the beneficiary key both change the address, and that the control block really
//! commits the script. The on-chain spend is covered by the regtest test in `liftv2_regtest.rs`.

#[cfg(test)]
mod claim_output_tests {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
    use bitcoin::taproot::{ControlBlock, TapNodeHash};
    use bitcoin::{Address, Network, ScriptBuf};
    use cube::constructive::contracts::fixed_split_vault_v1::claim::{
        claim_control_block, claim_script, claim_scriptpubkey, claim_taproot, parse_claim_script,
        parse_statement_op_return_script, statement_op_return_script, CLAIM_SCRIPT_LEN,
    };

    /// The statement digest under test.
    const DIGEST: [u8; 32] = [
        0x4a, 0x7f, 0x06, 0x24, 0xc1, 0xa7, 0xec, 0xc8, 0x5e, 0x60, 0x7c, 0x00, 0x54, 0x5b, 0x99,
        0x82, 0x65, 0xea, 0xba, 0xe2, 0x2f, 0xcf, 0x31, 0x11, 0xe4, 0xdb, 0x0c, 0x22, 0x43, 0xac,
        0xaa, 0x32,
    ];

    /// Bob's x-only key.
    const BOB_KEY: [u8; 32] = [0x21; 32];

    /// Carol's x-only key.
    const CAROL_KEY: [u8; 32] = [0x31; 32];

    /// The nothing-up-my-sleeve internal key used by `script_path_only_single`.
    ///
    /// Frozen here so that a change to the internal key — which would silently add or remove a
    /// key path — fails the test.
    const NUMS_INTERNAL_KEY: [u8; 32] = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a,
        0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80,
        0x3a, 0xc0,
    ];

    #[test]
    fn claim_script_has_the_frozen_layout() {
        let script = claim_script(DIGEST, BOB_KEY);

        // 1 Exact length: 0x20 + 32 + 0x75 + 0x20 + 32 + 0xac.
        assert_eq!(script.len(), CLAIM_SCRIPT_LEN);
        assert_eq!(CLAIM_SCRIPT_LEN, 68);

        // 2 Exact opcodes.
        assert_eq!(script[0], 0x20, "the digest must be pushed in full");
        assert_eq!(script[33], 0x75, "the digest push must be dropped");
        assert_eq!(script[34], 0x20, "the key must be pushed in full");
        assert_eq!(script[67], 0xac, "the leaf must end in OP_CHECKSIG");

        // 3 The constants are the ones passed in.
        assert_eq!(&script[1..33], &DIGEST);
        assert_eq!(&script[35..67], &BOB_KEY);

        // 4 The script parses back to the same pair.
        assert_eq!(parse_claim_script(&script), Some((DIGEST, BOB_KEY)));
    }

    #[test]
    fn parse_rejects_anything_that_is_not_a_claim_script() {
        let script = claim_script(DIGEST, BOB_KEY);

        // Truncated and extended.
        assert_eq!(parse_claim_script(&script[..67]), None);
        let mut longer = script.clone();
        longer.push(0x00);
        assert_eq!(parse_claim_script(&longer), None);

        // Wrong opcode in any of the four fixed positions.
        for index in [0usize, 33, 34, 67] {
            let mut tampered = script.clone();
            tampered[index] ^= 0xff;
            assert_eq!(
                parse_claim_script(&tampered),
                None,
                "opcode at {index} should be required"
            );
        }

        // A plausible but different script: OP_CHECKSIG with no digest commitment.
        let mut no_commitment = Vec::new();
        no_commitment.push(0x20);
        no_commitment.extend(BOB_KEY);
        no_commitment.push(0xac);
        assert_eq!(parse_claim_script(&no_commitment), None);
    }

    #[test]
    fn digest_and_beneficiary_both_change_the_address() {
        let base = claim_scriptpubkey(DIGEST, BOB_KEY).expect("spk");

        // A different digest must produce a different output.
        let mut other_digest = DIGEST;
        other_digest[0] ^= 0x01;
        assert_ne!(
            claim_scriptpubkey(other_digest, BOB_KEY).expect("spk"),
            base,
            "the address must commit to the statement digest"
        );

        // A different beneficiary must produce a different output.
        assert_ne!(
            claim_scriptpubkey(DIGEST, CAROL_KEY).expect("spk"),
            base,
            "the address must commit to the beneficiary"
        );
    }

    #[test]
    fn claim_output_has_no_key_path() {
        let taproot = claim_taproot(DIGEST, BOB_KEY);

        // 1 The internal key is the nothing-up-my-sleeve point, so no key pair is known for it and
        //   the key path cannot be used.
        assert_eq!(taproot.inner_key().serialize_xonly(), NUMS_INTERNAL_KEY);

        // 2 There is exactly one leaf.
        let tree = taproot.tree().expect("a script path exists");
        assert_eq!(tree.leaves().len(), 1);
        assert_eq!(tree.leaves()[0].tap_script(), claim_script(DIGEST, BOB_KEY));
    }

    #[test]
    fn control_block_commits_the_claim_script() {
        let taproot = claim_taproot(DIGEST, BOB_KEY);
        let spk = taproot.spk().expect("spk");
        let control_block = claim_control_block(DIGEST, BOB_KEY).expect("control block");

        // 1 A single-leaf control block is 33 bytes.
        assert_eq!(control_block.len(), 33);

        // 2 rust-bitcoin must accept the commitment: it rebuilds the merkle path from the control
        //   block and checks the resulting tweak against the output key.
        let secp = Secp256k1::new();
        let output_key = XOnlyPublicKey::from_slice(&spk[2..]).expect("output key");
        let control_block = ControlBlock::decode(&control_block).expect("decodable control block");
        assert!(
            control_block.verify_taproot_commitment(
                &secp,
                output_key,
                &ScriptBuf::from_bytes(claim_script(DIGEST, BOB_KEY))
            ),
            "the claim script must be committed by the control block"
        );

        // 3 The address derived from the scriptpubkey must round trip.
        let address = Address::from_script(&ScriptBuf::from_bytes(spk), Network::Regtest)
            .expect("valid address");
        assert_eq!(
            address.script_pubkey(),
            ScriptBuf::from_bytes(claim_scriptpubkey(DIGEST, BOB_KEY).expect("spk"))
        );
    }

    #[test]
    fn claim_address_matches_rust_bitcoin_taproot() {
        // Cross-check the claim taproot against rust-bitcoin's independent builder.
        let taproot = claim_taproot(DIGEST, BOB_KEY);
        let secp = Secp256k1::new();
        let tree = taproot.tree().expect("script path");
        let merkle_root = TapNodeHash::from_byte_array(tree.tap_branch());
        let internal = XOnlyPublicKey::from_slice(&NUMS_INTERNAL_KEY).expect("internal key");

        let reference = Address::p2tr(&secp, internal, Some(merkle_root), Network::Regtest);
        assert_eq!(
            hex::encode(taproot.spk().expect("spk")),
            hex::encode(reference.script_pubkey().as_bytes())
        );
    }

    #[test]
    fn statement_op_return_round_trips() {
        let script = statement_op_return_script(DIGEST);

        // Layout: OP_RETURN, push 4, "CBV1", push 32, digest.
        assert_eq!(script.len(), 39);
        assert_eq!(script[0], 0x6a);
        assert_eq!(&script[2..6], b"CBV1");

        assert_eq!(parse_statement_op_return_script(&script), Some(DIGEST));

        // Anything else must not parse as a statement commitment.
        let mut wrong_prefix = script.clone();
        wrong_prefix[2] = b'X';
        assert_eq!(parse_statement_op_return_script(&wrong_prefix), None);

        let mut wrong_len = script.clone();
        wrong_len.pop();
        assert_eq!(parse_statement_op_return_script(&wrong_len), None);
    }
}
