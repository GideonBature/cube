//! Bitcoin Core evidence for the LiftV2 deposit/refund edge of the ownership graph.
//!
//! `LiftV2` is the existing construct that makes a deposit recoverable: an output whose key path is
//! a MuSig aggregate of the participant and the Engine, and whose script path is the participant
//! alone after a relative timelock. This file is the evidence implementation.md asks for under
//! "complete signing, spending, refund and handover tests".
//!
//! Two tests:
//!
//! - `liftv2_address_matches_rust_bitcoin` cross-checks the repository's hand-rolled taproot
//!   tweaking against `rust-bitcoin`'s independent implementation. It runs everywhere, with no
//!   node.
//! - `liftv2_refund_is_rejected_before_maturity_and_accepted_after` funds the address on a real
//!   regtest node, attempts the refund before the relative timelock matures, mines past it, and
//!   attempts the refund again. It is skipped unless `CUBE_REGTEST_DATADIR` points at a running
//!   regtest datadir, because CI has no node.
//!
//! What is *not* covered: the MuSig2 key-path spend, the successor handover, and the dispute
//! branches. Those remain open.

#[cfg(test)]
mod liftv2_regtest_tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::taproot::{TapLeafHash, TapNodeHash};
    use bitcoin::{
        Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use cube::constructive::taproot::TapRoot;
    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
    use cube::transmutative::codec::csv::{CSVEncode, CSVFlag};
    use serde_json::json;
    use std::path::PathBuf;

    /// The relative timelock the LiftV2 refund branch commits to, in blocks.
    const REFUND_DELAY_BLOCKS: u16 = 12_960;

    /// Alice's deposit key.
    const ALICE_SECRET: [u8; 32] = [
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11,
    ];

    /// The Engine's deposit key. Never signs in these tests; it only enters the aggregate key.
    const ENGINE_SECRET: [u8; 32] = [
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22,
    ];

    /// Returns Alice's x-only public key.
    fn alice_xonly() -> [u8; 32] {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&ALICE_SECRET).expect("valid secret"),
        );
        keypair.x_only_public_key().0.serialize()
    }

    /// Returns the Engine's x-only public key.
    fn engine_xonly() -> [u8; 32] {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&ENGINE_SECRET).expect("valid secret"),
        );
        keypair.x_only_public_key().0.serialize()
    }

    /// Returns the LiftV2 taproot for the fixture keys.
    fn liftv2_taproot() -> TapRoot {
        return_liftv2_taproot(alice_xonly(), engine_xonly()).expect("taproot must construct")
    }

    // ---------------------------------------------------------------------------------------
    // Offline: the hand-rolled tweak must agree with rust-bitcoin.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn liftv2_address_matches_rust_bitcoin() {
        let taproot = liftv2_taproot();
        let tree = taproot.tree().expect("a script path exists");

        // 1 Exactly one leaf, which is the refund branch.
        assert_eq!(tree.leaves().len(), 1);
        let leaf = &tree.leaves()[0];
        let script = leaf.tap_script();

        // 2 The script is `<delay> OP_CSV OP_DROP <alice> OP_CHECKSIG`.
        assert_eq!(script, refund_script());

        // 3 The repository's scriptpubkey must equal rust-bitcoin's for the same internal key and
        //   merkle root. This is the independent check of the tweak computation.
        let secp = Secp256k1::new();
        let internal_xonly =
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&taproot.inner_key().serialize_xonly())
                .expect("valid internal key");
        let merkle_root = TapNodeHash::from_byte_array(tree.tap_branch());

        let reference = Address::p2tr(&secp, internal_xonly, Some(merkle_root), Network::Regtest);

        assert_eq!(
            hex::encode(taproot.spk().expect("spk")),
            hex::encode(reference.script_pubkey().as_bytes()),
            "the repository's taproot tweak disagrees with rust-bitcoin"
        );

        // 4 The control block must commit the refund script to the funded output key.
        //   `verify_taproot_commitment` rebuilds the merkle path from the control block and checks
        //   the resulting tweak against the output key, so this independently proves that the
        //   script the repository will put in a witness really is the one the address commits to.
        let control_block = taproot.control_block(0).expect("control block");
        let cb_bytes = control_block.to_vec();
        assert_eq!(cb_bytes.len(), 33, "single-leaf control block is 33 bytes");
        assert_eq!(
            hex::encode(&cb_bytes[1..33]),
            hex::encode(taproot.inner_key().serialize_xonly()),
            "the control block must carry the untweaked internal key"
        );

        let decoded_control_block =
            bitcoin::taproot::ControlBlock::decode(&cb_bytes).expect("decodable control block");
        let output_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(
            &reference.script_pubkey().as_bytes()[2..],
        )
        .expect("valid output key");
        let script_buf = ScriptBuf::from_bytes(script.clone());
        assert!(
            decoded_control_block.verify_taproot_commitment(&secp, output_key, &script_buf),
            "the refund script must be committed by the control block and output key"
        );
    }

    /// Builds the refund tapscript exactly as `return_liftv2_taproot` does.
    fn refund_script() -> Vec<u8> {
        let mut script = Vec::<u8>::new();
        script.extend(<Vec<u8> as CSVEncode>::csv_num_encode(
            CSVFlag::CSVThreeMonths,
        ));
        script.push(0xb2); // OP_CHECKSEQUENCEVERIFY
        script.push(0x75); // OP_DROP
        script.push(0x20); // push 32 bytes
        script.extend(alice_xonly());
        script.push(0xac); // OP_CHECKSIG
        script
    }

    // ---------------------------------------------------------------------------------------
    // Node-gated: the refund branch must be immature-until-mature and then spendable.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn liftv2_refund_is_rejected_before_maturity_and_accepted_after() {
        // 1 Skip when no regtest node is configured.
        let Some(rpc) = regtest_client() else {
            println!(
                "SKIPPED: set CUBE_REGTEST_DATADIR to a running regtest datadir to run this test"
            );
            return;
        };

        // 2 Ensure a wallet exists, then mature its coinbase outputs.
        //    A wallet is created once; a second run on the same datadir loads the existing one.
        // `createwallet` fails when the wallet exists and `loadwallet` fails when it is already
        // loaded, so both outcomes are tolerated; what matters is that `getnewaddress` works.
        if rpc
            .call::<serde_json::Value>("createwallet", &[json!("cube_liftv2")])
            .is_err()
        {
            let _ = rpc.call::<serde_json::Value>("loadwallet", &[json!("cube_liftv2")]);
        }

        let mining_address: String = rpc.call("getnewaddress", &[]).expect("getnewaddress");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(101), json!(mining_address)])
            .expect("mature coinbase");

        // 3 Derive the deposit address from the template and fund it.
        let taproot = liftv2_taproot();
        let deposit_spk = ScriptBuf::from_bytes(taproot.spk().expect("spk"));
        let deposit_address = Address::from_script(&deposit_spk, Network::Regtest)
            .expect("the scriptpubkey must be a valid address");

        let funding_txid: String = rpc
            .call(
                "sendtoaddress",
                &[json!(deposit_address.to_string()), json!(1.0)],
            )
            .expect("sendtoaddress");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm deposit");

        // 4 Read the funded output. The wallet knows this transaction, so its hex comes back
        //   without a txindex; the deposit output is located by its scriptpubkey.
        let wallet_tx: serde_json::Value = rpc
            .call("gettransaction", &[json!(funding_txid), json!(true)])
            .expect("gettransaction");
        let funding_tx: Transaction = bitcoin::consensus::deserialize(
            &hex::decode(wallet_tx["hex"].as_str().expect("hex")).expect("hex decode"),
        )
        .expect("decode funding transaction");
        let (vout_index, prevout) = funding_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| output.script_pubkey == deposit_spk)
            .map(|(index, output)| (index as u32, output.clone()))
            .expect("the deposit output must be present");

        let funding_outpoint = OutPoint {
            txid: funding_tx.compute_txid(),
            vout: vout_index,
        };

        // 5 Build and sign the refund transaction through the script path.
        let spend_address: String = rpc.call("getnewaddress", &[]).expect("getnewaddress");
        let spend_spk = address_to_script(&spend_address);
        let refund_tx = build_refund_tx(&taproot, funding_outpoint, &prevout, spend_spk);
        let refund_hex = bitcoin::consensus::encode::serialize_hex(&refund_tx);

        // 6 Before maturity the refund must be rejected by Bitcoin Core.
        let rejection: serde_json::Value = rpc
            .call("testmempoolaccept", &[json!([refund_hex.clone()])])
            .expect("testmempoolaccept");
        let allowed = rejection[0]["allowed"].as_bool().unwrap_or(false);
        assert!(
            !allowed,
            "an immature refund must not be accepted: {rejection}"
        );
        let reason = rejection[0]["reject-reason"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        assert!(
            reason.contains("non-BIP68-final") || reason.contains("non-final"),
            "expected a maturity rejection, got: {reason}"
        );
        println!("immature refund rejected with: {reason}");

        // 7 Mine past the relative timelock, in batches so a single RPC call cannot time out.
        let mut mined = 0u32;
        while mined < u32::from(REFUND_DELAY_BLOCKS) {
            let batch = (u32::from(REFUND_DELAY_BLOCKS) - mined).min(400);
            let _: Vec<String> = rpc
                .call("generatetoaddress", &[json!(batch), json!(mining_address)])
                .expect("mine past maturity");
            mined += batch;
        }

        // 8 Now the same transaction must be accepted and mine.
        let accepted: String = rpc
            .call("sendrawtransaction", &[json!(refund_hex)])
            .expect("the mature refund must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("mine the refund");

        // 9 The refund must be mined, not merely accepted into the mempool: `gettxout` only
        //   reports confirmed, unspent outputs.
        let refund_outpoint: serde_json::Value = rpc
            .call("gettxout", &[json!(accepted), json!(0)])
            .expect("gettxout");
        assert!(
            !refund_outpoint.is_null(),
            "the refund output must be confirmed and unspent"
        );
        println!("mature refund accepted in {}", accepted);
    }

    /// Returns a client for the configured regtest node, or `None`.
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

    /// Parses an address from the node into a scriptpubkey.
    fn address_to_script(address: &str) -> ScriptBuf {
        use std::str::FromStr;
        Address::from_str(address)
            .expect("valid address")
            .assume_checked()
            .script_pubkey()
    }

    /// Builds the tapscript refund transaction with Alice's BIP-340 signature.
    fn build_refund_tx(
        taproot: &TapRoot,
        funding_outpoint: OutPoint,
        prevout: &TxOut,
        spend_spk: ScriptBuf,
    ) -> Transaction {
        let tree = taproot.tree().expect("script path");
        let leaf = &tree.leaves()[0];
        let script = leaf.tap_script();
        let leaf_hash = TapLeafHash::from_byte_array(leaf.tapleaf_hash());
        let control_block = taproot.control_block(0).expect("control block").to_vec();

        // 1 The refund is a script-path spend with the relative timelock as its sequence.
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: funding_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(u32::from(REFUND_DELAY_BLOCKS)),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(prevout.value.to_sat() - 1_000),
                script_pubkey: spend_spk,
            }],
        };

        // 2 Sign the BIP-341 script-path sighash.
        //
        // The `u32` in the leaf tuple is the *code separator position*, not the leaf version: it
        // must be 0xffff_ffff when the script contains no `OP_CODESEPARATOR`, which is the case
        // here. Getting this wrong produces a well-formed signature over the wrong digest, which
        // Bitcoin Core reports as an invalid Schnorr signature.
        let secp = Secp256k1::new();
        let sighash = SighashCache::new(&tx)
            .taproot_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(prevout)),
                None,
                Some((leaf_hash, 0xffff_ffff)),
                TapSighashType::Default,
            )
            .expect("sighash");
        let keypair = Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&ALICE_SECRET).expect("valid secret"),
        );
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);

        // 2.a Self-check the signature before spending an RPC round trip on it.
        let alice_xonly = keypair.x_only_public_key().0;
        secp.verify_schnorr(&signature, &message, &alice_xonly)
            .expect("the fixture signature must verify locally");

        // 3 The witness is `<sig> <script> <control block>` for a tapscript CHECKSIG.
        tx.input[0].witness =
            Witness::from_slice(&[signature.serialize().to_vec(), script, control_block]);

        tx
    }
}
