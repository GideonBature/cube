//! End-to-end: a valid claim is backed by a real Groth16 proof, evaluated by Argo, and taken
//! after the challenge window.
//!
//! This is the node-backed completion of the assertion path. The expensive parts — Groth16 setup,
//! proving and Argo garbling — are ignored by default and must run in release:
//!
//! ```text
//! CUBE_REGTEST_RPC_URL=http://127.0.0.1:18443 \
//! CUBE_REGTEST_RPC_USER=cube CUBE_REGTEST_RPC_PASSWORD=cube \
//! cargo test --release --test proof_take_regtest -- --ignored --nocapture
//! ```
//!
//! It uses a single-party **trusted test setup**. It proves the integration and the settlement
//! path, not a deployment setup.

mod common;

mod proof_take_regtest {
    use ark_bn254::Fr;
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::{Address, Amount, Network, OutPoint, TxOut, Txid, Witness};
    use bitcoincore_rpc::RpcApi;
    use cube::constructive::graph::assertion::{
        Assertion, AssertionAnchor, AssertionClaim, AssertionTerms, ContestedOutput, TakeSpend,
    };
    use cube::model::fixed_split_vault_v1::manifest::{
        Anchor, Payout, PayoutKind, ReleaseProfile, TransitionManifest, MANIFEST_SCHEMA_VERSION,
    };
    use cube::model::fixed_split_vault_v1::{
        split_amounts, Auth, Ledger, Operation, Role, SplitDescriptor, SplitVault,
    };
    use cube_argo::{
        statement_public_input, GarbledVerifier, GarblingConfig, Groth16Proof as ArgoProof,
        Groth16VerifyingKey, PreparedVerifierKey, VerifierOutcome, RECOMMENDED_SETUP_STACK_BYTES,
    };
    use cube_proof::fund_split::FundSplitCircuit;
    use cube_proof::groth16::{prove, setup, verify};
    use serde_json::json;
    use std::str::FromStr;

    const OWNER_KEY: [u8; 32] = [0x21; 32];
    const BOB_KEY: [u8; 32] = [0x22; 32];
    const CAROL_KEY: [u8; 32] = [0x23; 32];
    const FEE_KEY: [u8; 32] = [0x24; 32];
    const GROSS_SATS: u64 = 100_000;
    const FEE_SATS: u64 = 500;
    const BENEFICIARY_SECRET: [u8; 32] = [0x41; 32];
    const OPERATOR_SECRET: [u8; 32] = [0x31; 32];
    const CLAIM_VALUE: u64 = 100_000;
    const ASSERT_FEE: u64 = 1_000;
    const TAKE_FEE: u64 = 500;
    const CHALLENGE_BLOCKS: u32 = 10;

    struct Fixture {
        manifest: TransitionManifest,
        previous_state: Vec<u8>,
        resulting_state: Vec<u8>,
        bob_sats: u64,
        carol_sats: u64,
    }

    fn fixture() -> Fixture {
        let descriptor = SplitDescriptor::new(
            [0x11; 32], [0x22; 32], OWNER_KEY, BOB_KEY, CAROL_KEY, FEE_KEY,
        );
        let mut vault = SplitVault::new(Ledger::new(GROSS_SATS, 0, 0, 0));
        vault
            .instantiate(
                descriptor,
                Auth::new(Role::Owner, 1),
                Operation::new(
                    SplitVault::next_operation_id(1),
                    SplitVault::payload_digest(b"instantiate"),
                ),
            )
            .expect("the fixture must instantiate");
        let previous_state = vault.state().encode();
        let previous_state_digest = vault.state_digest();

        vault
            .fund(
                GROSS_SATS,
                FEE_SATS,
                Auth::new(Role::Owner, 2),
                Operation::new(
                    SplitVault::next_operation_id(2),
                    SplitVault::payload_digest(b"fund"),
                ),
            )
            .expect("the fixture must fund");
        let resulting_state = vault.state().encode();
        let resulting_state_digest = vault.state_digest();
        let amounts = split_amounts(GROSS_SATS, FEE_SATS).expect("a valid split");

        let manifest = TransitionManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            profile: ReleaseProfile::ArgoSplitRegtest,
            network_genesis_hash: [0x11; 32],
            template_hash: [0x22; 32],
            circuit_id: [0x33; 32],
            verifier_key_digest: [0x44; 32],
            previous_state_digest,
            resulting_state_digest,
            batch_sequence: 1,
            anchors: vec![Anchor::new([0x77; 32], 0)],
            entry_digest: [0x88; 32],
            caller_key: OWNER_KEY,
            caller_sequence: 2,
            operation_id: [0xaa; 32],
            payouts: vec![
                Payout::new(BOB_KEY, amounts.bob_sats, PayoutKind::BeneficiaryAllocation),
                Payout::new(
                    CAROL_KEY,
                    amounts.carol_sats,
                    PayoutKind::BeneficiaryAllocation,
                ),
                Payout::new(FEE_KEY, FEE_SATS, PayoutKind::ExecutionFee),
            ],
            setup_instance_id: [0xbb; 32],
            graph_template_version: 1,
            challenge_config_digest: [0xcc; 32],
            recovery_package_digest: [0xdd; 32],
            batch_data_digest: [0xee; 32],
            availability_descriptor_digest: [0xff; 32],
        };
        manifest
            .validate()
            .expect("the fixture manifest must validate");

        Fixture {
            manifest,
            previous_state,
            resulting_state,
            bob_sats: amounts.bob_sats,
            carol_sats: amounts.carol_sats,
        }
    }

    fn keypair(secret: [u8; 32]) -> Keypair {
        let secp = Secp256k1::new();
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&secret).expect("key"))
    }

    fn xonly(secret: [u8; 32]) -> [u8; 32] {
        keypair(secret).x_only_public_key().0.serialize()
    }

    fn sign_digest(digest: [u8; 32], secret: [u8; 32]) -> [u8; 64] {
        let secp = Secp256k1::new();
        secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &keypair(secret))
            .serialize()
    }

    #[test]
    #[ignore = "Groth16 setup/proving and Argo garbling are slow; run in release with --ignored"]
    fn a_valid_proof_assertion_is_taken_after_the_challenge_window() {
        std::thread::Builder::new()
            .name("proof-take-regtest".to_string())
            .stack_size(RECOMMENDED_SETUP_STACK_BYTES)
            .spawn(scenario)
            .expect("spawn")
            .join()
            .expect("the scenario must not panic");
    }

    fn scenario() {
        // 1 Skip before the expensive cryptography when no node is configured.
        let Some(base) = crate::common::client(None) else {
            println!("SKIPPED: set CUBE_REGTEST_RPC_URL or CUBE_REGTEST_DATADIR to run this test");
            return;
        };

        // 2 A real proof for the fixture's statement.
        let fixture = fixture();
        let circuit = FundSplitCircuit::from_parts(
            fixture.manifest.encode(),
            fixture.previous_state.clone(),
            fixture.resulting_state.clone(),
            0,
        );
        let statement = circuit.statement;
        let statement_digest = fixture.manifest.statement_digest();
        assert_eq!(
            statement_public_input(statement_digest).expect("field-sized digest"),
            statement,
            "the circuit statement and the field-sized digest must agree"
        );

        let mut rng = StdRng::seed_from_u64(0xc0ff_ee00_1234_5678);
        let started = std::time::Instant::now();
        let proving_key = setup(circuit.clone(), &mut rng).expect("setup");
        println!("groth16 setup: {:?}", started.elapsed());
        let started = std::time::Instant::now();
        let proof = prove(circuit, &proving_key, &mut rng).expect("prove");
        println!("groth16 prove: {:?}", started.elapsed());
        assert!(
            verify(&proving_key.vk, statement, &proof).expect("verify"),
            "the honest proof must verify"
        );

        // 3 The same key in Argo's equation, and the table's verdict on the real proof.
        let verifier_key = Groth16VerifyingKey {
            alpha_g1: proving_key.vk.alpha_g1,
            beta_g2: proving_key.vk.beta_g2,
            gamma_g2: proving_key.vk.gamma_g2,
            delta_g2: proving_key.vk.delta_g2,
            gamma_abc_g1: proving_key.vk.gamma_abc_g1.clone(),
        };
        let prepared =
            PreparedVerifierKey::from_groth16_verifying_key(&verifier_key).expect("convert");
        let config = GarblingConfig {
            rng_seed: 0x5eed_5eed_5eed_5eed,
            disclosure_secret: vec![0x5a; 32],
        };
        let started = std::time::Instant::now();
        let verifier = GarbledVerifier::setup(&config, &prepared, [0x11; 16]).expect("garble");
        println!("garble: {:?}", started.elapsed());

        let honest = ArgoProof {
            a: proof.a,
            b: proof.b,
            c: proof.c,
            x: statement,
        };
        let authenticated = verifier.authenticate(&honest).expect("authenticate");
        assert_eq!(
            authenticated.public_input().expect("public input"),
            statement
        );
        assert_eq!(
            verifier
                .evaluate_authenticated(&authenticated)
                .expect("evaluate"),
            VerifierOutcome::Accepted,
            "a valid proof must not disclose"
        );

        // 4 A proof for another statement is not evidence: the table discloses.
        let wrong = ArgoProof {
            x: statement + Fr::from(1u64),
            ..honest
        };
        let wrong_authenticated = verifier.authenticate(&wrong).expect("authenticate wrong");
        assert_ne!(authenticated.digest(), wrong_authenticated.digest());
        assert_eq!(
            verifier
                .evaluate_authenticated(&wrong_authenticated)
                .expect("evaluate wrong"),
            VerifierOutcome::Disclosed
        );

        // 5 The claim and the assertion bind the authenticated input.
        if base
            .call::<serde_json::Value>("createwallet", &[json!("cube_proof_take")])
            .is_err()
        {
            let _ = base.call::<serde_json::Value>("loadwallet", &[json!("cube_proof_take")]);
        }
        let rpc = crate::common::client(Some("cube_proof_take")).expect("wallet client");
        let mining_address: String = rpc.call("getnewaddress", &[]).expect("getnewaddress");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(101), json!(mining_address)])
            .expect("mature coinbase");

        let beneficiary_key = xonly(BENEFICIARY_SECRET);
        let terms = AssertionTerms {
            statement_digest,
            claim_id: [0x71; 32],
            setup_instance_id: [0x11; 16],
            verifier_key_identity: prepared.identity(),
            table_digest: verifier.table_digest(),
            secret_commitment: verifier.disclosure_secret_commitment(),
            input_digest: authenticated.digest(),
            challenge_blocks: CHALLENGE_BLOCKS,
            operator_key: xonly(OPERATOR_SECRET),
            beneficiary_key,
        };
        let claim = AssertionClaim::new(statement_digest, terms.binding_digest(), beneficiary_key)
            .expect("claim");
        let claim_address =
            Address::from_script(&claim.scriptpubkey().expect("claim spk"), Network::Regtest)
                .expect("claim address");
        let funding_txid: String = rpc
            .call(
                "sendtoaddress",
                &[
                    json!(claim_address.to_string()),
                    json!(CLAIM_VALUE as f64 / 100_000_000.0),
                ],
            )
            .expect("fund the claim");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm claim");
        let (claim_outpoint, claim_prevout) = wallet_output(&rpc, &funding_txid, CLAIM_VALUE);

        let assertion = Assertion::new(
            terms.clone(),
            ContestedOutput {
                outpoint: claim_outpoint,
                value_sats: CLAIM_VALUE,
            },
            ASSERT_FEE,
        )
        .expect("assertion");
        let mut assert_tx = assertion.transaction(Witness::new()).expect("assert tx");
        let sighash = claim
            .assert_signing_hash(&assert_tx, &claim_prevout)
            .expect("assert sighash");
        assert_tx.input[0].witness = claim
            .assert_witness(sign_digest(sighash, BENEFICIARY_SECRET))
            .expect("claim witness");
        let assert_txid: String = rpc
            .call(
                "sendrawtransaction",
                &[json!(bitcoin::consensus::encode::serialize_hex(&assert_tx))],
            )
            .expect("the assertion must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm assertion");
        let assert_txid: Txid = assert_txid.parse().expect("txid");

        // 6 The operator cannot take before the challenge window.
        let destination = Address::from_str(
            &rpc.call::<String>("getnewaddress", &[])
                .expect("take address"),
        )
        .expect("address")
        .assume_checked()
        .script_pubkey();
        let assertion_prevout = TxOut {
            value: Amount::from_sat(CLAIM_VALUE - ASSERT_FEE),
            script_pubkey: assertion.scriptpubkey().expect("assertion spk"),
        };
        let take = TakeSpend::new(
            &assertion,
            AssertionAnchor::new(
                OutPoint {
                    txid: assert_txid,
                    vout: 0,
                },
                CLAIM_VALUE - ASSERT_FEE,
            ),
            destination.clone(),
            TAKE_FEE,
        )
        .expect("take");
        let mut take_tx = take.transaction();
        let sighash = take.signing_hash(&assertion_prevout).expect("take sighash");
        take_tx.input[0].witness = take
            .witness(sign_digest(sighash, OPERATOR_SECRET))
            .expect("take witness");
        let premature: serde_json::Value = rpc
            .call(
                "testmempoolaccept",
                &[json!([bitcoin::consensus::encode::serialize_hex(&take_tx)])],
            )
            .expect("testmempoolaccept");
        assert!(
            !premature[0]["allowed"].as_bool().unwrap_or(false),
            "a premature take must not be accepted: {premature}"
        );

        // 7 After the window, the valid claim is taken and the destination is paid.
        let _: Vec<String> = rpc
            .call(
                "generatetoaddress",
                &[json!(CHALLENGE_BLOCKS), json!(mining_address)],
            )
            .expect("advance the challenge window");
        let accepted: serde_json::Value = rpc
            .call(
                "testmempoolaccept",
                &[json!([bitcoin::consensus::encode::serialize_hex(&take_tx)])],
            )
            .expect("testmempoolaccept");
        assert!(
            accepted[0]["allowed"].as_bool().unwrap_or(false),
            "the mature take must be accepted: {accepted}"
        );
        let take_txid: String = rpc
            .call(
                "sendrawtransaction",
                &[json!(bitcoin::consensus::encode::serialize_hex(&take_tx))],
            )
            .expect("the take must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm take");
        let mined = mined_transaction(&rpc, take_txid.parse().expect("txid"));
        assert_eq!(
            mined.output[0].value,
            Amount::from_sat(CLAIM_VALUE - ASSERT_FEE - TAKE_FEE)
        );
        assert_eq!(mined.output[0].script_pubkey, destination);
        println!(
            "valid proof taken: assertion {assert_txid}, take {take_txid}, paid {} sats",
            mined.output[0].value.to_sat()
        );
        let _ = (fixture.bob_sats, fixture.carol_sats);
    }

    fn wallet_output(
        rpc: &bitcoincore_rpc::Client,
        txid: &str,
        value_sats: u64,
    ) -> (OutPoint, TxOut) {
        let wallet_tx: serde_json::Value = rpc
            .call("gettransaction", &[json!(txid), json!(true)])
            .expect("gettransaction");
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &hex::decode(wallet_tx["hex"].as_str().expect("hex")).expect("hex decode"),
        )
        .expect("transaction");
        for (vout, output) in tx.output.iter().enumerate() {
            if output.value.to_sat() == value_sats {
                return (
                    OutPoint {
                        txid: txid.parse().expect("txid"),
                        vout: vout as u32,
                    },
                    output.clone(),
                );
            }
        }
        panic!("the funding transaction has no output worth {value_sats} sats");
    }

    fn mined_transaction(rpc: &bitcoincore_rpc::Client, txid: Txid) -> bitcoin::Transaction {
        let block_hash: String = rpc
            .call(
                "getblockhash",
                &[json!(rpc
                    .call::<u64>("getblockcount", &[])
                    .expect("height"))],
            )
            .expect("block hash");
        let block: serde_json::Value = rpc
            .call("getblock", &[json!(block_hash), json!(2)])
            .expect("getblock");
        let tx = block["tx"]
            .as_array()
            .expect("tx array")
            .iter()
            .find(|tx| tx["txid"] == json!(txid))
            .expect("the transaction must be in the block");
        bitcoin::consensus::deserialize(
            &hex::decode(tx["hex"].as_str().expect("hex")).expect("hex decode"),
        )
        .expect("transaction")
    }
}
