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
    use cube::constructive::contracts::fixed_split_vault_v1::claim::{
        assertion_claim_scriptpubkey, parse_claim_script, parse_statement_op_return_script,
        statement_op_return_script,
    };
    use cube::constructive::contracts::fixed_split_vault_v1::recovery_package::ClaimRecoveryPackage;
    use cube::constructive::graph::assertion::{disclosure_secret_commitment, AssertionTerms};
    use cube::constructive::graph::claim_recovery::ClaimRecovery;
    use cube::constructive::graph::successor_funding::{DepositAnchor, SuccessorFunding};
    use cube::constructive::taproot::TapRoot;
    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::return_liftv2_taproot;
    use cube::model::fixed_split_vault_v1::manifest::{
        Payout, PayoutKind, ReleaseProfile, TransitionManifest, MANIFEST_SCHEMA_VERSION,
    };
    use cube::model::fixed_split_vault_v1::types::{Ledger, Role};
    use cube::model::fixed_split_vault_v1::{
        split_amounts, Anchor, Auth as ModelAuth, Operation, SplitDescriptor, SplitVault,
    };
    use cube::transmutative::codec::csv::{CSVEncode, CSVFlag};
    use cube::transmutative::hash::{Hash as CubeHash, HashTag};
    use cube::transmutative::musig::keyagg::MusigKeyAggCtx;
    use cube::transmutative::musig::session::MusigSessionCtx;
    use cube::transmutative::secp::schnorr::{self, SchnorrSigningMode};
    use secp::{Point, Scalar};
    use serde_json::json;
    use std::path::PathBuf;

    /// The relative timelock the LiftV2 refund branch commits to, in blocks.
    const REFUND_DELAY_BLOCKS: u16 = 12_960;

    /// Serialises the node-backed tests.
    ///
    /// They share one regtest node and one wallet, and one of them mines twelve thousand blocks,
    /// so they must not run concurrently even though the test harness runs tests in parallel.
    static NODE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Acquires the node-test lock, tolerating a lock poisoned by an earlier failing test.
    fn node_test_guard() -> std::sync::MutexGuard<'static, ()> {
        NODE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Alice's deposit key.
    const ALICE_SECRET: [u8; 32] = [
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11,
    ];

    /// Bob's secret key, used for his claim output.
    const BOB_SECRET: [u8; 32] = [
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
        0x33, 0x33,
    ];

    /// Carol's secret key, used for her claim output.
    const CAROL_SECRET: [u8; 32] = [
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55,
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
        let _node_guard = node_test_guard();

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

        // 7 Mine past the relative timelock.
        //
        // Batches are small because a single large `generatetoaddress` call can exceed the RPC
        // read timeout. A timed-out batch may still have mined, and mining extra blocks cannot
        // invalidate the test, so a retry is safe.
        let mut mined = 0u32;
        while mined < u32::from(REFUND_DELAY_BLOCKS) {
            let batch = (u32::from(REFUND_DELAY_BLOCKS) - mined).min(100);
            let mut attempts = 0;
            loop {
                match rpc.call::<Vec<String>>(
                    "generatetoaddress",
                    &[json!(batch), json!(mining_address)],
                ) {
                    Ok(_) => break,
                    Err(error) if attempts < 5 => {
                        attempts += 1;
                        println!("retrying block batch after transport error: {error}");
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                    Err(error) => panic!("mine past maturity: {error}"),
                }
            }
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

    // ---------------------------------------------------------------------------------------
    // Cooperative key path: MuSig2 over the taproot-tweaked aggregate key.
    // ---------------------------------------------------------------------------------------

    /// Returns the compressed point for an x-only key.
    fn point_from_xonly(key: [u8; 32]) -> Point {
        let mut compressed = Vec::<u8>::with_capacity(33);
        compressed.push(0x02);
        compressed.extend(key);
        Point::from_slice(&compressed).expect("valid point")
    }

    /// Returns the secret-key scalar of a fixture, normalised to the even-Y lift.
    ///
    /// `return_liftv2_taproot` lifts every x-only key to its even-Y point, so a signer whose
    /// secret produces an odd-Y point must negate its scalar to be recognised as that signer.
    fn scalar_of(secret: [u8; 32]) -> Scalar {
        let scalar = Scalar::from_slice(&secret).expect("valid scalar");
        scalar.negate_if(scalar.base_point_mul().parity())
    }

    /// Derives a deterministic MuSig2 nonce secret.
    ///
    /// Real deployments derive nonces with a fresh random seed and must never reuse them; a
    /// deterministic derivation is used here so the fixture is reproducible.
    fn secret_nonce(secret: [u8; 32], message: [u8; 32], index: u8) -> Scalar {
        let mut preimage = Vec::<u8>::with_capacity(65);
        preimage.extend(secret);
        preimage.extend(message);
        preimage.push(index);
        let digest = CubeHash::hash(
            &preimage,
            Some(HashTag::CustomString("Cube/musig/nonce/v0".to_string())),
        );
        Scalar::from_slice(&digest).expect("valid nonce scalar")
    }

    /// Returns the aggregate key context for the LiftV2 key path, with the taproot tweak applied.
    fn liftv2_key_agg_ctx(taproot: &TapRoot) -> MusigKeyAggCtx {
        let keys = vec![
            point_from_xonly(alice_xonly()),
            point_from_xonly(engine_xonly()),
        ];
        let tweak = Scalar::from_slice(&taproot.tap_tweak()).expect("valid taproot tweak");
        MusigKeyAggCtx::new(&keys, Some(tweak)).expect("key aggregation")
    }

    /// Produces a MuSig2 signature over `message` for the LiftV2 key path.
    ///
    /// Both signers are simulated in one process, which is adequate for the Bitcoin question being
    /// asked here (does the tweaked aggregate signature satisfy the output key?) but is not a
    /// multi-party protocol test.
    fn liftv2_musig_sign(taproot: &TapRoot, message: [u8; 32]) -> ([u8; 64], [u8; 32]) {
        let key_agg_ctx = liftv2_key_agg_ctx(taproot);
        let agg_key_xonly = key_agg_ctx.agg_key().serialize_xonly();

        let mut session = MusigSessionCtx::new(&key_agg_ctx, message).expect("session");

        // 1 Exchange public nonces.
        for (secret, key) in [
            (ALICE_SECRET, alice_xonly()),
            (ENGINE_SECRET, engine_xonly()),
        ] {
            let hiding = secret_nonce(secret, message, 0);
            let binding = secret_nonce(secret, message, 1);
            assert!(
                session.insert_nonce(
                    point_from_xonly(key),
                    hiding.base_point_mul(),
                    binding.base_point_mul(),
                ),
                "nonce insertion"
            );
        }
        assert!(session.ready(), "session must be ready with both nonces");

        // 2 Exchange partial signatures.
        for (secret, key) in [
            (ALICE_SECRET, alice_xonly()),
            (ENGINE_SECRET, engine_xonly()),
        ] {
            let hiding = secret_nonce(secret, message, 0);
            let binding = secret_nonce(secret, message, 1);
            let partial = session
                .partial_sign(scalar_of(secret), hiding, binding)
                .expect("partial signature");
            assert!(
                session.insert_partial_sig(point_from_xonly(key), partial),
                "partial signature insertion"
            );
        }

        // 3 Aggregate.
        let signature = session.full_agg_sig().expect("aggregate signature");
        (signature, agg_key_xonly)
    }

    /// With only one signer the aggregate must not exist, so the key path is not open to Alice
    /// alone. This is the reason a deposit cannot be taken unilaterally through the key path.
    #[test]
    fn liftv2_key_path_requires_both_signers() {
        let taproot = liftv2_taproot();
        let key_agg_ctx = liftv2_key_agg_ctx(&taproot);
        let message = [0xcdu8; 32];
        let mut session = MusigSessionCtx::new(&key_agg_ctx, message).expect("session");

        // 1 Only Alice contributes a nonce and a partial signature.
        let hiding = secret_nonce(ALICE_SECRET, message, 0);
        let binding = secret_nonce(ALICE_SECRET, message, 1);
        assert!(session.insert_nonce(
            point_from_xonly(alice_xonly()),
            hiding.base_point_mul(),
            binding.base_point_mul(),
        ));

        // 2 The session is not ready, so no aggregate nonce exists yet.
        assert!(!session.ready());
        assert!(session.agg_nonce().is_none());

        // 3 No signature can be aggregated. The blame list counts signers without a partial
        //   signature, which at this point is both of them.
        assert_eq!(session.blame_list().len(), 2);
        assert!(session.full_agg_sig().is_none());
    }

    #[test]
    fn liftv2_cooperative_key_path_signature_verifies() {
        let taproot = liftv2_taproot();

        // 1 The MuSig aggregate over the taproot tweak must equal the on-chain output key.
        let key_agg_ctx = liftv2_key_agg_ctx(&taproot);
        let spk = taproot.spk().expect("spk");
        assert_eq!(
            hex::encode(key_agg_ctx.agg_key().serialize_xonly()),
            hex::encode(&spk[2..34]),
            "the tweaked MuSig aggregate must equal the taproot output key"
        );

        // 2 A MuSig2 signature over an arbitrary message must verify against that key, using both
        //   the repository's verifier and the independent secp256k1 verifier.
        let message = [0xabu8; 32];
        let (signature, agg_key_xonly) = liftv2_musig_sign(&taproot, message);

        assert!(
            schnorr::verify_xonly(
                agg_key_xonly,
                message,
                signature,
                SchnorrSigningMode::BIP340
            ),
            "the repository's verifier rejected its own MuSig2 signature"
        );

        let secp = Secp256k1::new();
        secp.verify_schnorr(
            &bitcoin::secp256k1::schnorr::Signature::from_slice(&signature).expect("signature"),
            &Message::from_digest(message),
            &bitcoin::secp256k1::XOnlyPublicKey::from_slice(&agg_key_xonly).expect("key"),
        )
        .expect("secp256k1 rejected the MuSig2 signature");
    }

    // ---------------------------------------------------------------------------------------
    // Node-gated: the cooperative key-path spend.
    // ---------------------------------------------------------------------------------------

    #[test]
    fn liftv2_cooperative_key_path_spend_on_regtest() {
        // 1 Skip when no regtest node is configured.
        let Some(rpc) = regtest_client() else {
            println!(
                "SKIPPED: set CUBE_REGTEST_DATADIR to a running regtest datadir to run this test"
            );
            return;
        };

        let _node_guard = node_test_guard();

        // 2 Ensure a wallet exists and has mature funds.
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

        // 3 Fund the deposit address.
        let taproot = liftv2_taproot();
        let deposit_spk = ScriptBuf::from_bytes(taproot.spk().expect("spk"));
        let deposit_address =
            Address::from_script(&deposit_spk, Network::Regtest).expect("valid address");

        let funding_txid: String = rpc
            .call(
                "sendtoaddress",
                &[json!(deposit_address.to_string()), json!(0.5)],
            )
            .expect("sendtoaddress");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm deposit");

        // 4 Locate the funded output.
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

        // 5 Build the cooperative spend: key path, so the witness is the signature alone.
        let spend_spk = address_to_script(
            &rpc.call::<String>("getnewaddress", &[])
                .expect("getnewaddress"),
        );
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: funding_tx.compute_txid(),
                    vout: vout_index,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(prevout.value.to_sat() - 2_000),
                script_pubkey: spend_spk,
            }],
        };

        // 6 Sign the BIP-341 *key-path* sighash, which commits to no leaf at all.
        let sighash = SighashCache::new(&tx)
            .taproot_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&prevout)),
                None,
                None,
                TapSighashType::Default,
            )
            .expect("sighash");
        let (signature, agg_key_xonly) = liftv2_musig_sign(&taproot, sighash.to_byte_array());

        // 6.a The signature must satisfy the output key before any RPC round trip.
        let secp = Secp256k1::new();
        secp.verify_schnorr(
            &bitcoin::secp256k1::schnorr::Signature::from_slice(&signature).expect("signature"),
            &Message::from_digest(sighash.to_byte_array()),
            &bitcoin::secp256k1::XOnlyPublicKey::from_slice(&agg_key_xonly).expect("key"),
        )
        .expect("the cooperative signature must verify locally against the output key");

        tx.input[0].witness = Witness::from_slice(&[signature.to_vec()]);

        // 7 Bitcoin Core must accept the cooperative spend immediately: no timelock, no script.
        let accepted: String = rpc
            .call(
                "sendrawtransaction",
                &[json!(bitcoin::consensus::encode::serialize_hex(&tx))],
            )
            .expect("the cooperative key-path spend must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("mine the cooperative spend");

        let spent_outpoint: serde_json::Value = rpc
            .call("gettxout", &[json!(accepted), json!(0)])
            .expect("gettxout");
        assert!(
            !spent_outpoint.is_null(),
            "the cooperative output must be confirmed"
        );
        println!("cooperative key-path spend accepted in {accepted}");
    }

    // ---------------------------------------------------------------------------------------
    // Node-gated: successor funding that commits a statement, and a beneficiary claim.
    // ---------------------------------------------------------------------------------------

    /// Returns the x-only key of a fixture secret.
    fn xonly_of(secret: [u8; 32]) -> [u8; 32] {
        let secp = Secp256k1::new();
        Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&secret).expect("valid secret"),
        )
        .x_only_public_key()
        .0
        .serialize()
    }

    /// Signs a claim spend using only the bytes carried by a recovery package.
    ///
    /// This is the recovery path a fresh client takes: it never re-derives the script or control
    /// block from the statement, it uses what the package carries. The only thing it must supply
    /// from outside is the beneficiary secret key.
    fn sign_claim_spend_from_package(
        package: &ClaimRecoveryPackage,
        beneficiary_secret: [u8; 32],
        prevout: &TxOut,
        output_value: u64,
        output_spk: ScriptBuf,
    ) -> Transaction {
        // The recovery descriptor owns the shape and the sighash; this helper only signs.
        let fee_sats = prevout
            .value
            .to_sat()
            .checked_sub(output_value)
            .expect("the output must not exceed the claim");
        let recovery = ClaimRecovery::new(package, prevout, output_spk, fee_sats)
            .expect("the recovery descriptor must hold");
        let mut transaction = recovery.transaction();
        let sighash = recovery
            .signing_hash(prevout)
            .expect("the recovery sighash must compute");

        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&beneficiary_secret).expect("valid secret"),
        );
        let message = Message::from_digest(sighash);
        let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        secp.verify_schnorr(&signature, &message, &keypair.x_only_public_key().0)
            .expect("the claim signature must verify locally");

        transaction.input[0].witness = recovery.witness(signature.serialize());
        transaction
    }

    #[test]
    fn successor_funding_binds_the_statement_and_the_beneficiary_claims() {
        // 1 Skip without a node.
        let Some(rpc) = regtest_client() else {
            println!(
                "SKIPPED: set CUBE_REGTEST_DATADIR to a running regtest datadir to run this test"
            );
            return;
        };
        let _node_guard = node_test_guard();

        // 2 Wallet and mature funds.
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

        // 3 Fund the deposit through the LiftV2 key path.
        let taproot = liftv2_taproot();
        let deposit_spk = ScriptBuf::from_bytes(taproot.spk().expect("spk"));
        let deposit_address =
            Address::from_script(&deposit_spk, Network::Regtest).expect("valid address");
        let funding_txid: String = rpc
            .call(
                "sendtoaddress",
                &[json!(deposit_address.to_string()), json!(0.5)],
            )
            .expect("sendtoaddress");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("confirm deposit");

        let wallet_tx: serde_json::Value = rpc
            .call("gettransaction", &[json!(funding_txid), json!(true)])
            .expect("gettransaction");
        let deposit_tx: Transaction = bitcoin::consensus::deserialize(
            &hex::decode(wallet_tx["hex"].as_str().expect("hex")).expect("hex decode"),
        )
        .expect("decode deposit transaction");
        let (deposit_vout, deposit_prevout) = deposit_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| output.script_pubkey == deposit_spk)
            .map(|(index, output)| (index as u32, output.clone()))
            .expect("the deposit output must be present");
        let deposit_outpoint = OutPoint {
            txid: deposit_tx.compute_txid(),
            vout: deposit_vout,
        };

        // 4 Derive the split from the reference model, not by hand.
        const NETWORK_FEE_RESERVE: u64 = 2_000;
        let gross_sats = deposit_prevout.value.to_sat() - NETWORK_FEE_RESERVE;
        let execution_fee_sats: u64 = 5_000;
        let amounts = split_amounts(gross_sats, execution_fee_sats).expect("valid split");
        assert_eq!(
            amounts.bob_sats + amounts.carol_sats + execution_fee_sats,
            gross_sats
        );

        // 5 Build the accepted transition in the reference model and commit it in a manifest.
        let bob_key = xonly_of(BOB_SECRET);
        let carol_key = xonly_of(CAROL_SECRET);
        let fee_key = [0x66u8; 32];

        let descriptor = SplitDescriptor::new(
            [0x11; 32],
            [0x22; 32],
            alice_xonly(),
            bob_key,
            carol_key,
            fee_key,
        );
        let mut vault = SplitVault::new(Ledger::new(gross_sats, 0, 0, 0));
        vault
            .instantiate(
                descriptor,
                ModelAuth::new(Role::Owner, 1),
                Operation::new(
                    SplitVault::next_operation_id(1),
                    SplitVault::payload_digest(b"instantiate"),
                ),
            )
            .expect("model instantiate");
        let parent_digest = vault.state_digest();
        vault
            .fund(
                gross_sats,
                execution_fee_sats,
                ModelAuth::new(Role::Owner, 2),
                Operation::new(
                    SplitVault::next_operation_id(2),
                    SplitVault::payload_digest(b"fund"),
                ),
            )
            .expect("model fund");
        let resulting_digest = vault.state_digest();

        let manifest = TransitionManifest {
            schema_version: MANIFEST_SCHEMA_VERSION,
            profile: ReleaseProfile::ArgoSplitRegtest,
            network_genesis_hash: [0x11; 32],
            template_hash: cube::constructive::contracts::fixed_split_vault_v1::template_hash(),
            circuit_id: [0x33; 32],
            verifier_key_digest: [0x44; 32],
            previous_state_digest: parent_digest,
            resulting_state_digest: resulting_digest,
            batch_sequence: 1,
            anchors: vec![Anchor::new(
                deposit_outpoint.txid.to_byte_array(),
                deposit_outpoint.vout,
            )],
            entry_digest: [0x55; 32],
            caller_key: alice_xonly(),
            caller_sequence: 2,
            operation_id: [0x66; 32],
            payouts: vec![
                Payout::new(bob_key, amounts.bob_sats, PayoutKind::BeneficiaryAllocation),
                Payout::new(
                    carol_key,
                    amounts.carol_sats,
                    PayoutKind::BeneficiaryAllocation,
                ),
                Payout::new(fee_key, execution_fee_sats, PayoutKind::ExecutionFee),
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

        // 5.a The assertion setup supplies one binding per beneficiary. The successor emits a
        //     two-leaf claim for each; Bob's package below uses the same Bob binding.
        let bob_terms = AssertionTerms {
            statement_digest,
            claim_id: [0x71; 32],
            setup_instance_id: [0x77; 16],
            verifier_key_identity: [0x44; 32],
            table_digest: [0x45; 32],
            secret_commitment: disclosure_secret_commitment(&[0x46; 32]),
            input_digest: [0x47; 32],
            challenge_blocks: 144,
            operator_key: [0x31; 32],
            beneficiary_key: bob_key,
        };
        let carol_terms = AssertionTerms {
            claim_id: [0x72; 32],
            beneficiary_key: carol_key,
            ..bob_terms.clone()
        };
        let bindings = [bob_terms.binding_digest(), carol_terms.binding_digest()];

        // 6 Build the successor funding through the graph rule: it spends the deposit
        //   cooperatively and pays every obligation in manifest order. `new` runs the same verifier
        //   a signer runs, so an unfundable successor cannot reach the signing step.
        let fee_script = address_to_script(
            &rpc.call::<String>("getnewaddress", &[])
                .expect("fee address"),
        );
        let funding = SuccessorFunding::new_with_assertions(
            &manifest,
            DepositAnchor::new(deposit_outpoint, deposit_prevout.value.to_sat()),
            NETWORK_FEE_RESERVE,
            Some(fee_script),
            &bindings,
        )
        .expect("the successor must fund every manifest obligation");
        assert_eq!(funding.statement_digest(), statement_digest);
        assert_eq!(
            funding.outputs()[0].script_pubkey(),
            &ScriptBuf::from_bytes(
                assertion_claim_scriptpubkey(statement_digest, bindings[0], bob_key)
                    .expect("Bob's v2 claim")
            )
        );
        let mut successor = funding.transaction();

        // 6.a Sign the key path of the deposit with MuSig2.
        let sighash = SighashCache::new(&successor)
            .taproot_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&deposit_prevout)),
                None,
                None,
                TapSighashType::Default,
            )
            .expect("sighash");
        let (signature, agg_key_xonly) = liftv2_musig_sign(&taproot, sighash.to_byte_array());
        let secp = Secp256k1::new();
        secp.verify_schnorr(
            &bitcoin::secp256k1::schnorr::Signature::from_slice(&signature).expect("signature"),
            &Message::from_digest(sighash.to_byte_array()),
            &bitcoin::secp256k1::XOnlyPublicKey::from_slice(&agg_key_xonly).expect("key"),
        )
        .expect("the successor signature must verify locally");
        successor.input[0].witness = Witness::from_slice(&[signature.to_vec()]);

        // 6.b The statement is inside the signature scope. Bitcoin must accept the honest spend and
        //     reject the same spend once one committed digest byte changes: the MuSig2 key path
        //     signs the sighash, and the OP_RETURN commitment is part of it. This is the graph-level
        //     authorization the relation relies on instead of an in-circuit BIP-340 gadget.
        let honest_accept: serde_json::Value = rpc
            .call(
                "testmempoolaccept",
                &[json!([bitcoin::consensus::encode::serialize_hex(
                    &successor
                )])],
            )
            .expect("testmempoolaccept");
        assert_eq!(
            honest_accept[0]["allowed"],
            json!(true),
            "the honest successor must pass mempool acceptance"
        );

        let mut tampered_digest = statement_digest;
        tampered_digest[0] ^= 0x01;
        let mut tampered = successor.clone();
        tampered.output[3].script_pubkey =
            ScriptBuf::from_bytes(statement_op_return_script(tampered_digest));
        let tampered_accept: serde_json::Value = rpc
            .call(
                "testmempoolaccept",
                &[json!([bitcoin::consensus::encode::serialize_hex(
                    &tampered
                )])],
            )
            .expect("testmempoolaccept");
        assert_eq!(
            tampered_accept[0]["allowed"],
            json!(false),
            "a changed statement commitment must not be spendable under the same signature"
        );
        let reason = tampered_accept[0]["reject-reason"]
            .as_str()
            .unwrap_or_default();
        println!("tampered statement rejection: {reason}");
        assert!(
            reason.contains("script-verify") || reason.contains("schnorr"),
            "the rejection must be the signature check, got: {reason}"
        );

        // 7 Bitcoin Core must accept the successor funding.
        let successor_txid: String = rpc
            .call(
                "sendrawtransaction",
                &[json!(bitcoin::consensus::encode::serialize_hex(&successor))],
            )
            .expect("the successor funding must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("mine the successor funding");

        // 8 The statement commitment must be readable from the mined transaction itself.
        let block_hash: String = rpc
            .call(
                "getblockhash",
                &[json!(rpc.call::<u64>("getblockcount", &[]).expect("count"))],
            )
            .expect("block hash");
        let block: serde_json::Value = rpc
            .call("getblock", &[json!(block_hash), json!(2)])
            .expect("getblock");
        let mined = block["tx"]
            .as_array()
            .expect("tx array")
            .iter()
            .find(|tx| tx["txid"] == json!(successor_txid))
            .expect("the successor funding must be in the block");
        let committed = mined["vout"]
            .as_array()
            .expect("vout array")
            .iter()
            .filter_map(|output| {
                let hex_script = output["scriptPubKey"]["hex"].as_str()?;
                let bytes = hex::decode(hex_script).ok()?;
                parse_statement_op_return_script(&bytes)
            })
            .next()
            .expect("the statement commitment must be on-chain");
        assert_eq!(
            committed, statement_digest,
            "the on-chain commitment must be the statement digest"
        );

        // 9 Build Bob's v2 recovery package, then forget everything except its bytes.
        //
        // From here on the test uses only what the package carries: no statement digest, no
        // template call, no derived script. This is the shape of recovery after the Engine and the
        // original client are gone.
        let bob_claim_prevout = successor.output[0].clone();
        let bob_package = ClaimRecoveryPackage::new_with_assertion(
            ReleaseProfile::ArgoSplitRegtest,
            [0x71; 32],
            None,
            bob_key,
            manifest.template_hash,
            manifest.circuit_id,
            statement_digest,
            bindings[0],
            amounts.bob_sats,
            Some(Anchor::new(successor.compute_txid().to_byte_array(), 0)),
            432,
            10,
            manifest.setup_instance_id,
            manifest.challenge_config_digest,
        )
        .expect("Bob's package must construct");
        bob_package.validate().expect("Bob's package must be valid");

        // 9.a Transport it as bytes and decode, so recovery starts from the artifact and not from
        //     the values that happened to be in scope.
        let bob_package =
            ClaimRecoveryPackage::decode(&bob_package.encode()).expect("package round trip");
        assert_eq!(
            bob_package.claim_scriptpubkey().expect("spk"),
            bob_claim_prevout.script_pubkey.as_bytes(),
            "the package must recover the output that was actually funded"
        );
        assert!(bob_package.is_recoverable());

        // 9.b Carol signs with her own key against Bob's package; the script names Bob, so this
        //     must not be accepted.
        let carol_spend = sign_claim_spend_from_package(
            &bob_package,
            CAROL_SECRET,
            &bob_claim_prevout,
            bob_claim_prevout.value.to_sat() - 1_000,
            address_to_script(
                &rpc.call::<String>("getnewaddress", &[])
                    .expect("carol dest"),
            ),
        );
        let carol_result: serde_json::Value = rpc
            .call(
                "testmempoolaccept",
                &[json!([bitcoin::consensus::encode::serialize_hex(
                    &carol_spend
                )])],
            )
            .expect("testmempoolaccept");
        assert!(
            !carol_result[0]["allowed"].as_bool().unwrap_or(false),
            "another beneficiary must not spend Bob's claim: {carol_result}"
        );

        // 10 Bob spends his claim output, revealing the committed statement in the witness.
        let bob_spend = sign_claim_spend_from_package(
            &bob_package,
            BOB_SECRET,
            &bob_claim_prevout,
            bob_claim_prevout.value.to_sat() - 1_000,
            address_to_script(&rpc.call::<String>("getnewaddress", &[]).expect("bob dest")),
        );
        let bob_spend_txid: String = rpc
            .call(
                "sendrawtransaction",
                &[json!(bitcoin::consensus::encode::serialize_hex(&bob_spend))],
            )
            .expect("Bob's claim spend must be accepted");
        let _: Vec<String> = rpc
            .call("generatetoaddress", &[json!(1), json!(mining_address)])
            .expect("mine the claim spend");

        // 11 Read the spend back from the chain and confirm the witness revealed this statement.
        let block_hash: String = rpc
            .call(
                "getblockhash",
                &[json!(rpc.call::<u64>("getblockcount", &[]).expect("count"))],
            )
            .expect("block hash");
        let block: serde_json::Value = rpc
            .call("getblock", &[json!(block_hash), json!(2)])
            .expect("getblock");
        let mined_spend = block["tx"]
            .as_array()
            .expect("tx array")
            .iter()
            .find(|tx| tx["txid"] == json!(bob_spend_txid))
            .expect("the claim spend must be in the block");

        let witness = mined_spend["vin"][0]["txinwitness"]
            .as_array()
            .expect("witness array");
        let revealed_script =
            hex::decode(witness[1].as_str().expect("script item")).expect("script hex");
        let (revealed_digest, revealed_key) =
            parse_claim_script(&revealed_script).expect("the witness must reveal a claim script");
        assert_eq!(
            revealed_digest, statement_digest,
            "the revealed script must commit to the statement"
        );
        assert_eq!(revealed_key, bob_key);
        println!("successor funding {successor_txid}, Bob's claim {bob_spend_txid}");
    }
}
