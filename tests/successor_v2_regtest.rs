//! Bitcoin Core evidence that a successor can create two-leaf claims and that those claims keep
//! both of their exits: a beneficiary `Assert` that is disproved with the disclosure secret, and a
//! recovery through a v2 package.
//!
//! The deposit is a wallet output here so the test can sign the successor input; the successor
//! rule itself is the same one `tests/liftv2_regtest.rs` exercises through the MuSig2 key path. The
//! new ground is the successor's output shape: two v2 claims, each committed by a binding supplied
//! by the assertion setup, and each still spendable through its own leaf.
//!
//! Gated on `CUBE_REGTEST_DATADIR`; skips cleanly without a node.

mod common;

mod successor_v2_regtest {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::{Address, Amount, OutPoint, ScriptBuf, TxOut, Txid, Witness};
    use bitcoincore_rpc::{Client, RpcApi};
    use cube::constructive::contracts::fixed_split_vault_v1::recovery_package::ClaimRecoveryPackage;
    use cube::constructive::contracts::fixed_split_vault_v1::{
        assertion_claim_scriptpubkey, template_hash,
    };
    use cube::constructive::graph::assertion::{
        disclosure_secret_commitment, Assertion, AssertionAnchor, AssertionClaim, AssertionTerms,
        ContestedOutput, DisproveSpend,
    };
    use cube::constructive::graph::claim_recovery::ClaimRecovery;
    use cube::constructive::graph::successor_funding::{
        DepositAnchor, FeeBounds, SuccessorFunding,
    };
    use cube::model::fixed_split_vault_v1::manifest::{
        Anchor, Payout, PayoutKind, ReleaseProfile, TransitionManifest, MANIFEST_SCHEMA_VERSION,
    };
    use serde_json::json;
    use std::str::FromStr;

    const OPERATOR_SECRET: [u8; 32] = [0x31; 32];
    const BENEFICIARY_SECRET: [u8; 32] = [0x41; 32];
    const SECOND_SECRET: [u8; 32] = [0x42; 32];
    const FEE_KEY: [u8; 32] = [0x66; 32];
    const SECRET: [u8; 32] = [0x11; 32];
    const INSTANCE: [u8; 16] = [0x22; 16];
    const CLAIM_VALUE: u64 = 100_000;
    const SUCCESSOR_FEE: u64 = 500;
    const MINER_FEE: u64 = 1_000;
    const ASSERT_FEE: u64 = 1_000;
    const SPEND_FEE: u64 = 500;
    const CHALLENGE_BLOCKS: u32 = 144;
    const DEPOSIT_SATS: u64 = CLAIM_VALUE * 2 + SUCCESSOR_FEE + MINER_FEE;

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

    fn address_to_script(address: &str) -> ScriptBuf {
        Address::from_str(address)
            .expect("address")
            .assume_checked()
            .script_pubkey()
    }

    fn terms(
        statement_digest: [u8; 32],
        claim_id: [u8; 32],
        beneficiary_key: [u8; 32],
        operator_key: [u8; 32],
    ) -> AssertionTerms {
        AssertionTerms {
            statement_digest,
            claim_id,
            setup_instance_id: INSTANCE,
            verifier_key_identity: [0x51; 32],
            table_digest: [0x61; 32],
            secret_commitment: disclosure_secret_commitment(&SECRET),
            input_digest: [0x71; 32],
            challenge_blocks: CHALLENGE_BLOCKS,
            operator_key,
            beneficiary_key,
        }
    }

    #[test]
    fn a_successor_creates_two_leaf_claims_that_keep_both_exits() {
        let Some(base) = crate::common::client(None) else {
            println!(
                "SKIPPED: set CUBE_REGTEST_DATADIR to a running regtest datadir to run this test"
            );
            return;
        };

        // 1 A wallet with mature funds.
        if base
            .call::<serde_json::Value>("createwallet", &[json!("cube_successor_v2")])
            .is_err()
        {
            let _ = base.call::<serde_json::Value>("loadwallet", &[json!("cube_successor_v2")]);
        }
        let rpc = crate::common::client(Some("cube_successor_v2"))
            .expect("the wallet client must construct");
        let mining_address: String = rpc.call("getnewaddress", &[]).expect("getnewaddress");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(101), json!(mining_address)])
            .expect("mature coinbase");
        let destination = address_to_script(
            &rpc.call::<String>("getnewaddress", &[])
                .expect("destination address"),
        );

        // 2 The deposit the successor spends. A wallet-owned output keeps this test focused on the
        //   successor's outputs; the MuSig2 deposit path has its own test.
        let deposit_txid: String = rpc
            .call(
                "sendtoaddress",
                &[
                    json!(mining_address),
                    json!(DEPOSIT_SATS as f64 / 100_000_000.0),
                ],
            )
            .expect("fund the deposit");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm the deposit");
        let (deposit_outpoint, _deposit_prevout) = wallet_output(&rpc, &deposit_txid, DEPOSIT_SATS);

        // 3 The manifest binds two beneficiary allocations and one execution fee.
        let beneficiary_key = xonly(BENEFICIARY_SECRET);
        let second_key = xonly(SECOND_SECRET);
        let manifest = TransitionManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            profile: ReleaseProfile::ArgoSplitRegtest,
            network_genesis_hash: [0x11; 32],
            template_hash: template_hash(),
            circuit_id: [0x33; 32],
            verifier_key_digest: [0x44; 32],
            previous_state_digest: [0x55; 32],
            resulting_state_digest: [0x66; 32],
            batch_sequence: 1,
            anchors: vec![Anchor::new(
                deposit_outpoint.txid.to_byte_array(),
                deposit_outpoint.vout,
            )],
            entry_digest: [0x88; 32],
            caller_key: beneficiary_key,
            caller_sequence: 2,
            operation_id: [0xaa; 32],
            payouts: vec![
                Payout::new(
                    beneficiary_key,
                    CLAIM_VALUE,
                    PayoutKind::BeneficiaryAllocation,
                ),
                Payout::new(second_key, CLAIM_VALUE, PayoutKind::BeneficiaryAllocation),
                Payout::new(FEE_KEY, SUCCESSOR_FEE, PayoutKind::ExecutionFee),
            ],
            setup_instance_id: [0x77; 32],
            graph_template_version: 1,
            challenge_config_digest: [0x88; 32],
            recovery_package_digest: [0x99; 32],
            batch_data_digest: [0xaa; 32],
            availability_descriptor_digest: [0xbb; 32],
        };
        manifest.validate().expect("the manifest must be valid");
        let statement_digest = manifest.statement_digest();

        // 4 The two bindings the assertion setup supplies, and the successor that emits them.
        let terms_a = terms(
            statement_digest,
            [0x40; 32],
            beneficiary_key,
            xonly(OPERATOR_SECRET),
        );
        let terms_b = terms(
            statement_digest,
            [0x41; 32],
            second_key,
            xonly(OPERATOR_SECRET),
        );
        let bindings = [terms_a.binding_digest(), terms_b.binding_digest()];

        let funding = SuccessorFunding::new_with_assertions(
            &manifest,
            DepositAnchor::new(deposit_outpoint, DEPOSIT_SATS),
            MINER_FEE,
            Some(destination.clone()),
            &bindings,
        )
        .expect("the successor must fund every obligation");

        // 5 Sign the deposit input with the wallet and publish the successor.
        let successor = funding.transaction();
        let signed: serde_json::Value = rpc
            .call(
                "signrawtransactionwithwallet",
                &[json!(bitcoin::consensus::encode::serialize_hex(&successor))],
            )
            .expect("sign the successor");
        assert!(
            signed["complete"].as_bool().unwrap_or(false),
            "the wallet must complete the successor input"
        );
        let successor_txid: Txid = rpc
            .call(
                "sendrawtransaction",
                &[json!(signed["hex"].as_str().expect("signed hex"))],
            )
            .expect("the successor must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm the successor");
        let successor_tx = wallet_transaction(&rpc, successor_txid);

        // 6 The successor's two claims are the v2 scripts the bindings imply.
        for (index, (key, binding)) in [(beneficiary_key, bindings[0]), (second_key, bindings[1])]
            .iter()
            .enumerate()
        {
            let expected = assertion_claim_scriptpubkey(statement_digest, *binding, *key)
                .expect("v2 claim script");
            assert_eq!(
                successor_tx.output[index].script_pubkey,
                ScriptBuf::from_bytes(expected)
            );
            assert_eq!(
                successor_tx.output[index].value,
                Amount::from_sat(CLAIM_VALUE)
            );
        }

        // 7 Assert the first claim, then disprove it with the disclosure secret.
        let claim_a_outpoint = OutPoint {
            txid: successor_txid,
            vout: 0,
        };
        let claim_a_prevout = successor_tx.output[0].clone();
        let assertion = Assertion::new(
            terms_a.clone(),
            ContestedOutput {
                outpoint: claim_a_outpoint,
                value_sats: CLAIM_VALUE,
            },
            ASSERT_FEE,
        )
        .expect("assertion");
        let claim =
            AssertionClaim::new(statement_digest, terms_a.binding_digest(), beneficiary_key)
                .expect("claim");
        let mut assert_tx = assertion.transaction(Witness::new()).expect("assert tx");
        let sighash = claim
            .assert_signing_hash(&assert_tx, &claim_a_prevout)
            .expect("assert sighash");
        assert_tx.input[0].witness = claim
            .assert_witness(sign_digest(sighash, BENEFICIARY_SECRET))
            .expect("claim witness");
        let assert_txid: Txid = rpc
            .call(
                "sendrawtransaction",
                &[json!(bitcoin::consensus::encode::serialize_hex(&assert_tx))],
            )
            .expect("the assertion must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm the assertion");

        let assertion_anchor = AssertionAnchor::new(
            OutPoint {
                txid: assert_txid,
                vout: 0,
            },
            CLAIM_VALUE - ASSERT_FEE,
        );
        let assertion_prevout = TxOut {
            value: Amount::from_sat(CLAIM_VALUE - ASSERT_FEE),
            script_pubkey: assertion.scriptpubkey().expect("assertion spk"),
        };
        let disprove = DisproveSpend::new(
            &assertion,
            assertion_anchor,
            SECRET,
            destination.clone(),
            SPEND_FEE,
        )
        .expect("disprove");
        let mut disprove_tx = disprove.transaction();
        let sighash = disprove
            .signing_hash(&assertion_prevout)
            .expect("disprove sighash");
        disprove_tx.input[0].witness = disprove
            .witness(sign_digest(sighash, BENEFICIARY_SECRET))
            .expect("disprove witness");
        let disprove_txid: Txid = rpc
            .call(
                "sendrawtransaction",
                &[json!(bitcoin::consensus::encode::serialize_hex(
                    &disprove_tx
                ))],
            )
            .expect("the disprove must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm the disprove");
        assert_eq!(
            wallet_transaction(&rpc, disprove_txid).output[0].value,
            Amount::from_sat(CLAIM_VALUE - ASSERT_FEE - SPEND_FEE)
        );

        // 8 Recover the second claim through its v2 package.
        let claim_b_outpoint = OutPoint {
            txid: successor_txid,
            vout: 1,
        };
        let claim_b_prevout = successor_tx.output[1].clone();
        let height: u64 = rpc.call("getblockcount", &[]).expect("height");
        let package = ClaimRecoveryPackage::new_with_assertion(
            ReleaseProfile::ArgoSplitRegtest,
            [0x60; 32],
            None,
            second_key,
            [0x62; 32],
            [0x63; 32],
            statement_digest,
            terms_b.binding_digest(),
            CLAIM_VALUE,
            Some(Anchor {
                txid: claim_b_outpoint.txid.to_byte_array(),
                vout: claim_b_outpoint.vout,
            }),
            height + 144,
            2,
            [0x64; 32],
            [0x65; 32],
        )
        .expect("the v2 package must construct");
        assert_eq!(
            package.claim_scriptpubkey(),
            Some(claim_b_prevout.script_pubkey.as_bytes().to_vec())
        );
        let recovery =
            ClaimRecovery::new(&package, &claim_b_prevout, destination.clone(), SPEND_FEE)
                .expect("v2 recovery");
        let sighash = recovery
            .signing_hash(&claim_b_prevout)
            .expect("recovery sighash");
        let mut recovery_tx = recovery.transaction();
        recovery_tx.input[0].witness = recovery.witness(sign_digest(sighash, SECOND_SECRET));
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
            .expect("confirm the recovery");
        assert_eq!(
            wallet_transaction(&rpc, recovery_txid).output[0].value,
            Amount::from_sat(CLAIM_VALUE - SPEND_FEE)
        );

        // 9 The v1 verifier does not accept the v2 successor shape.
        assert!(matches!(
            SuccessorFunding::verify(
                &successor,
                &manifest,
                deposit_outpoint,
                DEPOSIT_SATS,
                FeeBounds::new(MINER_FEE, MINER_FEE),
            ),
            Err(cube::constructive::graph::successor_funding::SuccessorFundingError::PayoutOutputMismatch { index: 0 })
        ));
    }

    /// Finds the first output of `txid` worth `value_sats` and returns its outpoint.
    fn wallet_output(rpc: &Client, txid: &str, value_sats: u64) -> (OutPoint, TxOut) {
        let tx = wallet_transaction(rpc, Txid::from_str(txid).expect("txid"));
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

    /// Reads a wallet transaction through `gettransaction`, which does not need a txindex.
    fn wallet_transaction(rpc: &Client, txid: Txid) -> bitcoin::Transaction {
        let wallet_tx: serde_json::Value = rpc
            .call("gettransaction", &[json!(txid), json!(true)])
            .expect("gettransaction");
        bitcoin::consensus::deserialize(
            &hex::decode(wallet_tx["hex"].as_str().expect("hex")).expect("transaction hex"),
        )
        .expect("transaction")
    }
}
