//! Bitcoin Core evidence for the `ExitRequest` role.
//!
//! The offline tests pin the script and the commitment. This test publishes a real notice on a
//! regtest node, reads it back from the mined block, and verifies the terms against it. It is
//! gated on `CUBE_REGTEST_DATADIR` and skips cleanly without a node.

mod exit_request_regtest {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use cube::constructive::graph::exit_request::{ExitRequest, ExitTerms};
    use serde_json::json;
    use std::path::PathBuf;

    /// Returns a client for the regtest node, or `None` when no node is configured.
    fn regtest_client() -> Option<Client> {
        let datadir = std::env::var("CUBE_REGTEST_DATADIR").ok()?;
        if datadir.trim().is_empty() {
            return None;
        }

        let port = std::env::var("CUBE_REGTEST_RPC_PORT").unwrap_or_else(|_| "18443".to_string());
        let cookie = PathBuf::from(&datadir).join("regtest/.cookie");
        Client::new(
            &format!("http://127.0.0.1:{port}"),
            Auth::CookieFile(cookie),
        )
        .ok()
    }

    #[test]
    fn an_exit_request_is_recorded_and_verifiable_on_regtest() {
        let Some(rpc) = regtest_client() else {
            println!(
                "SKIPPED: set CUBE_REGTEST_DATADIR to a running regtest datadir to run this test"
            );
            return;
        };

        // 1 A wallet with mature funds.
        if rpc
            .call::<serde_json::Value>("createwallet", &[json!("cube_exit")])
            .is_err()
        {
            let _ = rpc.call::<serde_json::Value>("loadwallet", &[json!("cube_exit")]);
        }
        let mining_address: String = rpc.call("getnewaddress", &[]).expect("getnewaddress");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(101), json!(mining_address)])
            .expect("mature coinbase");

        let height: u64 = rpc.call("getblockcount", &[]).expect("height");

        // 2 The terms a participant would publish.
        let terms = ExitTerms::new(
            OutPoint {
                txid: Txid::from_byte_array([0x71; 32]),
                vout: 3,
            },
            [0x0a; 32],
            height + 144,
            [0x5b; 32],
            [0x6c; 32],
        );
        let request = ExitRequest::new(&terms);

        // 3 Build the notice around one wallet UTXO and let the wallet fund the change.
        let unspent: serde_json::Value = rpc.call("listunspent", &[json!(1)]).expect("listunspent");
        let utxo = unspent
            .as_array()
            .and_then(|entries| entries.first())
            .expect("a spendable output");

        let funding = OutPoint {
            txid: utxo["txid"].as_str().expect("txid").parse().expect("txid"),
            vout: utxo["vout"].as_u64().expect("vout") as u32,
        };
        let unsigned = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: request.script(),
            }],
        };
        let unsigned_hex = bitcoin::consensus::encode::serialize_hex(&unsigned);

        let funded: serde_json::Value = rpc
            .call("fundrawtransaction", &[json!(unsigned_hex)])
            .expect("fundrawtransaction");
        let signed: serde_json::Value = rpc
            .call(
                "signrawtransactionwithwallet",
                &[json!(funded["hex"].as_str().expect("hex"))],
            )
            .expect("signrawtransactionwithwallet");
        assert!(
            signed["complete"].as_bool().unwrap_or(false),
            "the wallet must complete the notice signature"
        );

        let txid: String = rpc
            .call("sendrawtransaction", &[json!(signed["hex"])])
            .expect("the notice must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("mine the notice");

        // 4 Read the notice back from the mined transaction. The wallet created it, so
        //   `gettransaction` returns its hex without requiring a txindex.
        let wallet_tx: serde_json::Value = rpc
            .call("gettransaction", &[json!(txid), json!(true)])
            .expect("gettransaction");
        let raw = hex::decode(wallet_tx["hex"].as_str().expect("hex")).expect("decode");
        let mined: Transaction =
            bitcoin::consensus::deserialize(&raw).expect("deserialize the mined notice");

        let output = mined
            .output
            .iter()
            .find(|output| output.script_pubkey == request.script())
            .expect("the notice output must be in the transaction");
        assert_eq!(output.value.to_sat(), 0, "the notice carries no value");

        let recorded =
            ExitRequest::parse(output.script_pubkey.as_bytes()).expect("the notice must parse");

        // 5 The recorded notice commits exactly the terms the participant published.
        assert_eq!(recorded, request);
        assert_eq!(recorded.verify(&terms), Ok(()));

        let mut changed = terms;
        changed.deadline_height += 1;
        assert!(
            recorded.verify(&changed).is_err(),
            "a changed deadline must not verify against the recorded commitment"
        );

        println!(
            "exit request {txid} recorded for claim {:?}",
            terms.claim_outpoint
        );
    }
}
