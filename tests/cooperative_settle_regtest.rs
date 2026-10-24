//! Bitcoin Core evidence for the `CooperativeSettle` edge.
//!
//! Two v2 claims are funded, then spent in one transaction to two native destinations. The claim
//! signatures are `SIGHASH_ALL`, so each beneficiary signs the whole settlement: redirecting one
//! output invalidates both signatures. The fee input is an ordinary P2TR UTXO and its whole value
//! is the miner fee.
//!
//! Gated on `CUBE_REGTEST_DATADIR`; skips cleanly without a node.

mod cooperative_settle_regtest {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::TapTweakHash;
    use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, TxOut, Txid, Witness};
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use cube::constructive::contracts::fixed_split_vault_v1::recovery_package::ClaimRecoveryPackage;
    use cube::constructive::graph::assertion::{
        disclosure_secret_commitment, AssertionClaim, AssertionTerms,
    };
    use cube::constructive::graph::cooperative_settle::{CooperativeSettle, SETTLE_INPUT_SEQUENCE};
    use cube::constructive::graph::successor_funding::FeeBounds;
    use cube::model::fixed_split_vault_v1::manifest::{
        Anchor, Payout, PayoutKind, ReleaseProfile, TransitionManifest, MANIFEST_SCHEMA_VERSION,
    };
    use serde_json::json;
    use std::path::PathBuf;
    use std::str::FromStr;

    const BOB_SECRET: [u8; 32] = [0x41; 32];
    const CAROL_SECRET: [u8; 32] = [0x42; 32];
    const OPERATOR_SECRET: [u8; 32] = [0x31; 32];
    const FEE_SECRET: [u8; 32] = [0x77; 32];
    const SECRET: [u8; 32] = [0x11; 32];
    const INSTANCE: [u8; 16] = [0x22; 16];
    const CLAIM_VALUE: u64 = 100_000;
    const FEE_INPUT_SATS: u64 = 2_000;

    fn regtest_client(wallet: Option<&str>) -> Option<Client> {
        let datadir = std::env::var("CUBE_REGTEST_DATADIR").ok()?;
        if datadir.trim().is_empty() {
            return None;
        }
        let port = std::env::var("CUBE_REGTEST_RPC_PORT").unwrap_or_else(|_| "18443".to_string());
        let cookie = PathBuf::from(&datadir).join("regtest/.cookie");
        let path = wallet
            .map(|name| format!("/wallet/{name}"))
            .unwrap_or_default();
        Client::new(
            &format!("http://127.0.0.1:{port}{path}"),
            Auth::CookieFile(cookie),
        )
        .ok()
    }

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
            challenge_blocks: 144,
            operator_key,
            beneficiary_key,
        }
    }

    #[test]
    fn a_whole_claim_tree_settles_in_one_transaction() {
        let Some(base) = regtest_client(None) else {
            println!(
                "SKIPPED: set CUBE_REGTEST_DATADIR to a running regtest datadir to run this test"
            );
            return;
        };
        if base
            .call::<serde_json::Value>("createwallet", &[json!("cube_coop_settle")])
            .is_err()
        {
            let _ = base.call::<serde_json::Value>("loadwallet", &[json!("cube_coop_settle")]);
        }
        let rpc = regtest_client(Some("cube_coop_settle")).expect("wallet client");
        let mining_address: String = rpc.call("getnewaddress", &[]).expect("getnewaddress");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(101), json!(mining_address)])
            .expect("mature coinbase");

        // 1 The manifest comes first: the statement digest is what every claim binds.
        let bob_key = xonly(BOB_SECRET);
        let carol_key = xonly(CAROL_SECRET);
        let manifest = TransitionManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            profile: ReleaseProfile::ArgoSplitRegtest,
            network_genesis_hash: [0x11; 32],
            template_hash: [0x22; 32],
            circuit_id: [0x33; 32],
            verifier_key_digest: [0x44; 32],
            previous_state_digest: [0x55; 32],
            resulting_state_digest: [0x66; 32],
            batch_sequence: 1,
            anchors: vec![Anchor::new([0x77; 32], 0)],
            entry_digest: [0x88; 32],
            caller_key: [0x99; 32],
            caller_sequence: 2,
            operation_id: [0xaa; 32],
            payouts: vec![
                Payout::new(bob_key, CLAIM_VALUE, PayoutKind::BeneficiaryAllocation),
                Payout::new(carol_key, CLAIM_VALUE, PayoutKind::BeneficiaryAllocation),
                Payout::new([0x23; 32], 500, PayoutKind::ExecutionFee),
            ],
            setup_instance_id: [0xbb; 32],
            graph_template_version: 1,
            challenge_config_digest: [0xcc; 32],
            recovery_package_digest: [0xdd; 32],
            batch_data_digest: [0xee; 32],
            availability_descriptor_digest: [0xff; 32],
        };
        manifest.validate().expect("manifest");
        let statement_digest = manifest.statement_digest();

        // 2 Fund two v2 claims directly. The claim shape is the same one the successor emits.
        let bob_terms = terms(
            statement_digest,
            [0x40; 32],
            bob_key,
            xonly(OPERATOR_SECRET),
        );
        let carol_terms = terms(
            statement_digest,
            [0x41; 32],
            carol_key,
            xonly(OPERATOR_SECRET),
        );
        let mut claims = Vec::new();
        for (terms, key) in [(&bob_terms, bob_key), (&carol_terms, carol_key)] {
            let claim =
                AssertionClaim::new(statement_digest, terms.binding_digest(), key).expect("claim");
            let address =
                Address::from_script(&claim.scriptpubkey().expect("claim spk"), Network::Regtest)
                    .expect("claim address");
            let funding_txid: String = rpc
                .call(
                    "sendtoaddress",
                    &[
                        json!(address.to_string()),
                        json!(CLAIM_VALUE as f64 / 100_000_000.0),
                    ],
                )
                .expect("fund the claim");
            let _: Vec<String> = rpc
                .call("generatetoaddress", &[json!(1), json!(mining_address)])
                .expect("confirm the claim");
            let (outpoint, prevout) = wallet_output(&rpc, &funding_txid, CLAIM_VALUE);
            claims.push(((*terms).clone(), claim, outpoint, prevout));
        }

        // 3 A local P2TR fee input: its whole value is the miner fee.
        let fee_key = keypair(FEE_SECRET);
        let fee_xonly = fee_key.x_only_public_key().0;
        let secp = Secp256k1::new();
        let fee_address = Address::p2tr(&secp, fee_xonly, None, Network::Regtest);
        let fee_txid: String = rpc
            .call(
                "sendtoaddress",
                &[
                    json!(fee_address.to_string()),
                    json!(FEE_INPUT_SATS as f64 / 100_000_000.0),
                ],
            )
            .expect("fund the fee input");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm the fee input");
        let (fee_outpoint, fee_prevout) = wallet_output(&rpc, &fee_txid, FEE_INPUT_SATS);

        // 4 The two v2 packages. The execution fee is already settled by the successor and is not
        //   part of this claim tree.
        let packages: Vec<ClaimRecoveryPackage> = claims
            .iter()
            .zip([&bob_terms, &carol_terms])
            .map(|((_, _, outpoint, _), terms)| {
                ClaimRecoveryPackage::new_with_assertion(
                    ReleaseProfile::ArgoSplitRegtest,
                    terms.claim_id,
                    None,
                    terms.beneficiary_key,
                    [0x22; 32],
                    [0x33; 32],
                    statement_digest,
                    terms.binding_digest(),
                    CLAIM_VALUE,
                    Some(Anchor {
                        txid: outpoint.txid.to_byte_array(),
                        vout: outpoint.vout,
                    }),
                    432,
                    10,
                    [0xbb; 32],
                    [0xcc; 32],
                )
                .expect("package")
            })
            .collect();

        // 5 The settlement pays both claims, in manifest order, to wallet destinations.
        let destinations = vec![
            address_to_script(&rpc.call::<String>("getnewaddress", &[]).expect("bob dest")),
            address_to_script(
                &rpc.call::<String>("getnewaddress", &[])
                    .expect("carol dest"),
            ),
        ];
        let settlement = CooperativeSettle::new(
            &manifest,
            &packages,
            destinations.clone(),
            fee_outpoint,
            &fee_prevout,
            FeeBounds::new(FEE_INPUT_SATS, FEE_INPUT_SATS),
        )
        .expect("settlement");

        let prevouts = [
            claims[0].3.clone(),
            claims[1].3.clone(),
            fee_prevout.clone(),
        ];
        let mut transaction = settlement.transaction();
        for (index, _) in claims.iter().enumerate() {
            let sighash = settlement
                .claim_signing_hash(index, &prevouts)
                .expect("claim sighash");
            let secret = if index == 0 { BOB_SECRET } else { CAROL_SECRET };
            transaction.input[index].witness = settlement
                .claim_witness(index, sign_digest(sighash, secret))
                .expect("claim witness");
        }

        // The fee input is a P2TR key path; every signature covers the whole transaction.
        let fee_sighash = SighashCache::new(&transaction)
            .taproot_signature_hash(
                2,
                &Prevouts::All(&prevouts),
                None,
                None,
                TapSighashType::Default,
            )
            .expect("fee sighash");
        let fee_tweak = TapTweakHash::from_key_and_tweak(fee_xonly, None).to_scalar();
        let fee_signer = fee_key
            .add_xonly_tweak(&secp, &fee_tweak)
            .expect("the tweaked fee key");
        let fee_signature = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(fee_sighash.to_byte_array()),
            &fee_signer,
        );
        transaction.input[2].witness = Witness::from_slice(&[fee_signature.serialize().to_vec()]);

        // 6 Redirecting one output breaks both claim signatures.
        let mut redirected = transaction.clone();
        redirected.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
        let rejected: serde_json::Value = rpc
            .call(
                "testmempoolaccept",
                &[json!([bitcoin::consensus::encode::serialize_hex(
                    &redirected
                )])],
            )
            .expect("testmempoolaccept");
        assert!(
            !rejected[0]["allowed"].as_bool().unwrap_or(false),
            "a redirected settlement must not be accepted: {rejected}"
        );

        // 7 The honest settlement is accepted and confirms.
        let txid: Txid = rpc
            .call(
                "sendrawtransaction",
                &[json!(bitcoin::consensus::encode::serialize_hex(
                    &transaction
                ))],
            )
            .expect("the settlement must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm the settlement");

        let mined = mined_transaction(&rpc, txid);
        assert_eq!(mined.input.len(), 3);
        assert_eq!(mined.output.len(), 2);
        assert_eq!(mined.output[0].value, Amount::from_sat(CLAIM_VALUE));
        assert_eq!(mined.output[0].script_pubkey, destinations[0]);
        assert_eq!(mined.output[1].value, Amount::from_sat(CLAIM_VALUE));
        assert_eq!(mined.output[1].script_pubkey, destinations[1]);
        for (index, (_, _, outpoint, _)) in claims.iter().enumerate() {
            assert_eq!(mined.input[index].previous_output, *outpoint);
            assert_eq!(mined.input[index].sequence, SETTLE_INPUT_SEQUENCE);
        }
        assert_eq!(mined.input[2].previous_output, fee_outpoint);
    }

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

    fn wallet_transaction(rpc: &Client, txid: Txid) -> bitcoin::Transaction {
        let wallet_tx: serde_json::Value = rpc
            .call("gettransaction", &[json!(txid), json!(true)])
            .expect("gettransaction");
        bitcoin::consensus::deserialize(
            &hex::decode(wallet_tx["hex"].as_str().expect("hex")).expect("transaction hex"),
        )
        .expect("transaction")
    }

    fn mined_transaction(rpc: &Client, txid: Txid) -> bitcoin::Transaction {
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
            &hex::decode(tx["hex"].as_str().expect("hex")).expect("transaction hex"),
        )
        .expect("transaction")
    }
}
