//! Bitcoin Core evidence for the `Assert`, `Take` and `Disprove` edges.
//!
//! The offline tests pin the scripts. This test creates a real assertion output on a regtest node
//! and shows that Bitcoin accepts the honest spends and rejects premature, redirected and
//! wrong-secret ones. It is gated on `CUBE_REGTEST_DATADIR` and skips cleanly without a node.

mod common;

mod assertion_regtest {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::TapLeafHash;
    use bitcoin::{Address, Amount, Network, OutPoint, TxOut, Txid, Witness};
    use bitcoincore_rpc::{Client, RpcApi};
    use cube::constructive::contracts::fixed_split_vault_v1::recovery_package::ClaimRecoveryPackage;
    use cube::constructive::graph::assertion::{
        disclosure_secret_commitment, Assertion, AssertionAnchor, AssertionClaim, AssertionTerms,
        ContestedOutput, DisproveSpend, TakeSpend,
    };
    use cube::constructive::graph::claim_recovery::ClaimRecovery;
    use cube::model::fixed_split_vault_v1::manifest::Anchor;
    use cube::model::fixed_split_vault_v1::ReleaseProfile;
    use serde_json::json;
    use std::str::FromStr;

    const OPERATOR_SECRET: [u8; 32] = [0x31; 32];
    const BENEFICIARY_SECRET: [u8; 32] = [0x41; 32];
    const SECRET: [u8; 32] = [0x11; 32];
    const OTHER_SECRET: [u8; 32] = [0x12; 32];
    const INSTANCE: [u8; 16] = [0x22; 16];
    const STATEMENT: [u8; 32] = [0x0a; 32];
    const CLAIM_VALUE: u64 = 100_000;
    const ASSERT_FEE: u64 = 1_000;
    const SPEND_FEE: u64 = 500;
    const CHALLENGE_BLOCKS: u32 = 144;

    fn keypair(secret: [u8; 32]) -> Keypair {
        let secp = Secp256k1::new();
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&secret).expect("valid key"))
    }

    fn xonly(secret: [u8; 32]) -> [u8; 32] {
        keypair(secret).x_only_public_key().0.serialize()
    }

    fn sign_digest(digest: [u8; 32], secret: [u8; 32]) -> [u8; 64] {
        let secp = Secp256k1::new();
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(secret))
            .serialize()
    }

    fn sign_script_path(
        tx: &bitcoin::Transaction,
        prevout: &TxOut,
        script: &[u8],
        secret: [u8; 32],
    ) -> [u8; 64] {
        let secp = Secp256k1::new();
        let leaf_hash = TapLeafHash::from_byte_array(cube::constructive::taproot::hash_tap_leaf(
            &script.to_vec(),
            0xc0,
        ));
        let sighash = SighashCache::new(tx)
            .taproot_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(prevout)),
                None,
                Some((leaf_hash, 0xffff_ffff)),
                TapSighashType::Default,
            )
            .expect("sighash");
        let signature = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sighash.to_byte_array()),
            &keypair(secret),
        );
        signature.serialize()
    }

    #[test]
    fn assertion_take_and_disprove_are_enforced_on_regtest() {
        let Some(base) = crate::common::client(None) else {
            println!(
                "SKIPPED: set CUBE_REGTEST_DATADIR to a running regtest datadir to run this test"
            );
            return;
        };

        // 1 A wallet with mature funds.
        if base
            .call::<serde_json::Value>("createwallet", &[json!("cube_assertion")])
            .is_err()
        {
            let _ = base.call::<serde_json::Value>("loadwallet", &[json!("cube_assertion")]);
        }
        let rpc = crate::common::client(Some("cube_assertion"))
            .expect("the wallet client must construct");
        let mining_address: String = rpc.call("getnewaddress", &[]).expect("getnewaddress");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(101), json!(mining_address)])
            .expect("mature coinbase");

        let destination: String = rpc.call("getnewaddress", &[]).expect("getnewaddress");
        let destination_script = Address::from_str(&destination)
            .expect("address")
            .assume_checked()
            .script_pubkey();

        let secp_operator = xonly(OPERATOR_SECRET);
        let secp_beneficiary = xonly(BENEFICIARY_SECRET);

        // 2 Build one assertion per path. The claim is a v2 taproot funded by the wallet; the
        //   `Assert` input is signed by the beneficiary through the assertion leaf, not by the
        //   wallet. That is the signature the binding description relies on.
        let mut assertions = Vec::new();
        for index in 0..2u8 {
            let terms = AssertionTerms {
                statement_digest: STATEMENT,
                claim_id: [0x40 + index; 32],
                setup_instance_id: INSTANCE,
                verifier_key_identity: [0x51; 32],
                table_digest: [0x61; 32],
                secret_commitment: disclosure_secret_commitment(&SECRET),
                input_digest: [0x71; 32],
                challenge_blocks: CHALLENGE_BLOCKS,
                operator_key: secp_operator,
                beneficiary_key: secp_beneficiary,
            };
            let claim = AssertionClaim::new(STATEMENT, terms.binding_digest(), secp_beneficiary)
                .expect("claim");
            let claim_address =
                Address::from_script(&claim.scriptpubkey().expect("claim spk"), Network::Regtest)
                    .expect("claim address");
            let funding_txid: String = rpc
                .call(
                    "sendtoaddress",
                    &[json!(claim_address.to_string()), json!(0.001)],
                )
                .expect("fund the claim");
            let _: Vec<String> = rpc
                .call("generatetoaddress", &[json!(1), json!(mining_address)])
                .expect("confirm claim");
            let (claim_outpoint, claim_prevout) = wallet_output(&rpc, &funding_txid, CLAIM_VALUE);

            let contested = ContestedOutput {
                outpoint: claim_outpoint,
                value_sats: CLAIM_VALUE,
            };
            let assertion = Assertion::new(terms, contested, ASSERT_FEE).expect("assertion");

            // BIP-141 excludes the witness from the txid, so the assertion output is already at its
            // final outpoint before the beneficiary signs.
            let mut unsigned = assertion.transaction(Witness::new()).expect("assert tx");
            let sighash = claim
                .assert_signing_hash(&unsigned, &claim_prevout)
                .expect("assert sighash");

            // The assertion leaf is the beneficiary's, not the operator's.
            let mut wrong_assert = unsigned.clone();
            wrong_assert.input[0].witness = claim
                .assert_witness(sign_digest(sighash, OPERATOR_SECRET))
                .expect("operator witness");
            let rejected = test_mempool_accept(
                &rpc,
                &bitcoin::consensus::encode::serialize_hex(&wrong_assert),
            );
            assert!(
                !rejected["allowed"].as_bool().unwrap_or(false),
                "the operator must not be able to sign the claim assertion leaf: {rejected}"
            );

            unsigned.input[0].witness = claim
                .assert_witness(sign_digest(sighash, BENEFICIARY_SECRET))
                .expect("claim witness");
            let txid: Txid = rpc
                .call(
                    "sendrawtransaction",
                    &[json!(bitcoin::consensus::encode::serialize_hex(&unsigned))],
                )
                .expect("the assertion must be accepted");
            assert_eq!(
                txid,
                unsigned.compute_txid(),
                "the witness signature must not move the assertion outpoint"
            );

            let outpoint = OutPoint { txid, vout: 0 };
            let prevout = TxOut {
                value: Amount::from_sat(CLAIM_VALUE - ASSERT_FEE),
                script_pubkey: assertion.scriptpubkey().expect("spk"),
            };
            assertions.push((
                assertion,
                AssertionAnchor::new(outpoint, prevout.value.to_sat()),
                prevout,
            ));
            let _: Vec<String> = rpc
                .call("generatetoaddress", &[json!(1), json!(mining_address)])
                .expect("confirm assertion");
        }

        // 3 A Take before the challenge window is rejected by the relative timelock.
        let (take_assertion, take_anchor, take_prevout) = &assertions[0];
        let take = TakeSpend::new(
            take_assertion,
            *take_anchor,
            destination_script.clone(),
            SPEND_FEE,
        )
        .expect("take");
        let mut take_tx = take.transaction();
        let signature = sign_script_path(
            &take_tx,
            take_prevout,
            &take_assertion.take_script(),
            OPERATOR_SECRET,
        );
        take_tx.input[0].witness = take.witness(signature).expect("witness");
        let take_hex = bitcoin::consensus::encode::serialize_hex(&take_tx);
        let rejected = test_mempool_accept(&rpc, &take_hex);
        assert!(
            !rejected["allowed"].as_bool().unwrap_or(false),
            "a premature Take must not be accepted: {rejected}"
        );

        // 4 A Disprove with the wrong secret is rejected by the hashlock.
        let (disprove_assertion, disprove_anchor, disprove_prevout) = &assertions[1];
        let disprove = DisproveSpend::new(
            disprove_assertion,
            *disprove_anchor,
            SECRET,
            destination_script.clone(),
            SPEND_FEE,
        )
        .expect("disprove");
        let mut wrong_secret_tx = disprove.transaction();
        let signature = sign_script_path(
            &wrong_secret_tx,
            disprove_prevout,
            &disprove_assertion.disprove_script(),
            BENEFICIARY_SECRET,
        );
        wrong_secret_tx.input[0].witness = Witness::from_slice(&[
            signature.to_vec(),
            OTHER_SECRET.to_vec(),
            disprove_assertion.disprove_script(),
            disprove_assertion
                .disprove_control_block()
                .expect("control block"),
        ]);
        let rejected = test_mempool_accept(
            &rpc,
            &bitcoin::consensus::encode::serialize_hex(&wrong_secret_tx),
        );
        assert!(
            !rejected["allowed"].as_bool().unwrap_or(false),
            "a wrong secret must not spend the disprove leaf: {rejected}"
        );

        // 5 The honest Disprove is accepted and confirms.
        let mut unsigned_disprove = disprove.transaction();
        unsigned_disprove.input[0].witness = Witness::from_slice(&[
            vec![0x00; 64],
            SECRET.to_vec(),
            disprove_assertion.disprove_script(),
            disprove_assertion
                .disprove_control_block()
                .expect("control block"),
        ]);
        let rejected = test_mempool_accept(
            &rpc,
            &bitcoin::consensus::encode::serialize_hex(&unsigned_disprove),
        );
        assert!(
            !rejected["allowed"].as_bool().unwrap_or(false),
            "a disprove without the beneficiary signature must not be accepted: {rejected}"
        );

        let mut disprove_tx = disprove.transaction();
        let signature = sign_script_path(
            &disprove_tx,
            disprove_prevout,
            &disprove_assertion.disprove_script(),
            BENEFICIARY_SECRET,
        );
        disprove_tx.input[0].witness = disprove.witness(signature).expect("witness");
        let disprove_hex = bitcoin::consensus::encode::serialize_hex(&disprove_tx);
        let accepted = test_mempool_accept(&rpc, &disprove_hex);
        assert!(
            accepted["allowed"].as_bool().unwrap_or(false),
            "the honest disprove must be accepted: {accepted}"
        );
        let disprove_txid: Txid = rpc
            .call("sendrawtransaction", &[json!(disprove_hex)])
            .expect("broadcast disprove");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm disprove");
        let mined: serde_json::Value = rpc
            .call("gettransaction", &[json!(disprove_txid), json!(true)])
            .expect("disprove included");
        assert_eq!(mined["confirmations"].as_u64().unwrap_or(0), 1);

        // 6 After the challenge window the same Take is accepted.
        let _: Vec<String> = rpc
            .call(
                "generatetoaddress",
                &[json!(CHALLENGE_BLOCKS), json!(mining_address)],
            )
            .expect("advance the challenge window");

        // The timelock is satisfied, but only the operator key can take.
        let mut wrong_signer = take.transaction();
        let signature = sign_script_path(
            &wrong_signer,
            take_prevout,
            &take_assertion.take_script(),
            BENEFICIARY_SECRET,
        );
        wrong_signer.input[0].witness = take.witness(signature).expect("witness");
        let rejected = test_mempool_accept(
            &rpc,
            &bitcoin::consensus::encode::serialize_hex(&wrong_signer),
        );
        assert!(
            !rejected["allowed"].as_bool().unwrap_or(false),
            "a take signed by the beneficiary must not be accepted: {rejected}"
        );

        let accepted = test_mempool_accept(&rpc, &take_hex);
        assert!(
            accepted["allowed"].as_bool().unwrap_or(false),
            "the mature Take must be accepted: {accepted}"
        );
        let take_txid: Txid = rpc
            .call("sendrawtransaction", &[json!(take_hex)])
            .expect("broadcast take");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm take");
        let mined: serde_json::Value = rpc
            .call("gettransaction", &[json!(take_txid), json!(true)])
            .expect("take included");
        assert_eq!(mined["confirmations"].as_u64().unwrap_or(0), 1);

        // 7 A two-leaf claim keeps its recovery leaf. Fund one more claim and spend it through a
        //   v2 package, without touching the assertion leaf.
        let recovery_terms = AssertionTerms {
            statement_digest: STATEMENT,
            claim_id: [0x50; 32],
            setup_instance_id: INSTANCE,
            verifier_key_identity: [0x51; 32],
            table_digest: [0x61; 32],
            secret_commitment: disclosure_secret_commitment(&SECRET),
            input_digest: [0x71; 32],
            challenge_blocks: CHALLENGE_BLOCKS,
            operator_key: secp_operator,
            beneficiary_key: secp_beneficiary,
        };
        let recovery_claim =
            AssertionClaim::new(STATEMENT, recovery_terms.binding_digest(), secp_beneficiary)
                .expect("recovery claim");
        let recovery_address = Address::from_script(
            &recovery_claim.scriptpubkey().expect("recovery claim spk"),
            Network::Regtest,
        )
        .expect("recovery claim address");
        let recovery_funding: String = rpc
            .call(
                "sendtoaddress",
                &[json!(recovery_address.to_string()), json!(0.001)],
            )
            .expect("fund the recovery claim");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm the recovery claim");
        let (recovery_outpoint, recovery_prevout) =
            wallet_output(&rpc, &recovery_funding, CLAIM_VALUE);

        let height: u64 = rpc.call("getblockcount", &[]).expect("height");
        let package = ClaimRecoveryPackage::new_with_assertion(
            ReleaseProfile::ArgoSplitRegtest,
            [0x60; 32],
            None,
            secp_beneficiary,
            [0x62; 32],
            [0x63; 32],
            STATEMENT,
            recovery_terms.binding_digest(),
            CLAIM_VALUE,
            Some(Anchor {
                txid: recovery_outpoint.txid.to_byte_array(),
                vout: recovery_outpoint.vout,
            }),
            height + 144,
            2,
            [0x64; 32],
            [0x65; 32],
        )
        .expect("the v2 recovery package must construct");
        let recovery = ClaimRecovery::new(
            &package,
            &recovery_prevout,
            destination_script.clone(),
            SPEND_FEE,
        )
        .expect("v2 recovery");
        let sighash = recovery
            .signing_hash(&recovery_prevout)
            .expect("recovery sighash");
        let mut recovery_tx = recovery.transaction();
        recovery_tx.input[0].witness = recovery.witness(sign_digest(sighash, BENEFICIARY_SECRET));
        let recovery_txid: Txid = rpc
            .call(
                "sendrawtransaction",
                &[json!(bitcoin::consensus::encode::serialize_hex(
                    &recovery_tx
                ))],
            )
            .expect("the v2 recovery must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm the v2 recovery");
        let mined: serde_json::Value = rpc
            .call("gettransaction", &[json!(recovery_txid), json!(true)])
            .expect("recovery included");
        assert_eq!(mined["confirmations"].as_u64().unwrap_or(0), 1);
    }

    /// Finds the first output of `txid` worth `value_sats` and returns its outpoint.
    fn wallet_output(rpc: &Client, txid: &str, value_sats: u64) -> (OutPoint, TxOut) {
        let wallet_tx: serde_json::Value = rpc
            .call("gettransaction", &[json!(txid), json!(true)])
            .expect("gettransaction");
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &hex::decode(wallet_tx["hex"].as_str().expect("hex")).expect("transaction hex"),
        )
        .expect("transaction");
        for (vout, output) in tx.output.iter().enumerate() {
            if output.value.to_sat() == value_sats {
                return (
                    OutPoint {
                        txid: Txid::from_str(txid).expect("txid"),
                        vout: vout as u32,
                    },
                    output.clone(),
                );
            }
        }
        panic!("the funding transaction has no output worth {value_sats} sats");
    }

    fn test_mempool_accept(rpc: &Client, raw_hex: &str) -> serde_json::Value {
        let result: serde_json::Value = rpc
            .call("testmempoolaccept", &[json!([raw_hex])])
            .expect("testmempoolaccept");
        result
            .as_array()
            .and_then(|entries| entries.first())
            .cloned()
            .expect("one mempool acceptance result")
    }
}
