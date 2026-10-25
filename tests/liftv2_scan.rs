//! The node's UTXO scan must find the LiftV2 outputs the ownership graph deposits into.
//!
//! The scan is what turns a funded output into a `Lift` the node CLI can lift. The Liftup decoder
//! and executor already accept V2; this test pins the scan switch in both directions, so turning
//! `V2_LIFT_ENABLED` on cannot silently stop finding V1 or start seeing a V2 output that is not
//! there.

#[cfg(test)]
mod liftv2_scan_tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
    use cube::constructive::txo::lift::lift::Lift;
    use cube::constructive::txo::lift::lift_versions::liftv1::liftv1::return_liftv1_scriptpubkey;
    use cube::constructive::txo::lift::lift_versions::liftv2::liftv2::return_liftv2_scriptpubkey;
    use cube::inscriptive::utxo_set::utxo_set::{erase_utxo_set, UTXOSet};
    use cube::operative::run_args::chain::Chain;
    use cube::transmutative::key::KeyHolder;

    /// Alice's account key.
    const ACCOUNT_SECRET: [u8; 32] = [0x11; 32];
    /// The Engine's key.
    const ENGINE_SECRET: [u8; 32] = [0x22; 32];
    /// A second participant.
    const OTHER_SECRET: [u8; 32] = [0x33; 32];

    fn txout(script: Vec<u8>, sats: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::from_bytes(script),
        }
    }

    fn outpoint(seed: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([seed; 32]),
            vout: 0,
        }
    }

    #[tokio::test]
    async fn the_scan_finds_v1_and_v2_only_when_enabled() {
        let chain = Chain::Testbed;
        erase_utxo_set(chain);
        let utxo_set = UTXOSet::new(chain).expect("utxo set");
        let account_key = KeyHolder::new(ACCOUNT_SECRET)
            .expect("account key")
            .secp_public_key_bytes();
        let engine_key = KeyHolder::new(ENGINE_SECRET)
            .expect("engine key")
            .secp_public_key_bytes();
        let other_key = KeyHolder::new(OTHER_SECRET)
            .expect("other key")
            .secp_public_key_bytes();

        // 1 One V1 output and one V2 output for the same pair of keys.
        let v1_script =
            return_liftv1_scriptpubkey(account_key, engine_key).expect("v1 scriptpubkey");
        let v2_script =
            return_liftv2_scriptpubkey(account_key, engine_key).expect("v2 scriptpubkey");
        {
            let mut set = utxo_set.lock().await;
            set.insert_utxo(&outpoint(0x01), &txout(v1_script, 100_000));
            set.insert_utxo(&outpoint(0x02), &txout(v2_script, 200_000));
        }

        // 2 With V2 enabled, both are found, and the V2 one is labelled as such.
        let mut versions = {
            let set = utxo_set.lock().await;
            set.scan_and_return_self_owned_lifts(&engine_key, &account_key, true)
                .iter()
                .map(Lift::lift_version)
                .collect::<Vec<_>>()
        };
        versions.sort_unstable();
        assert_eq!(versions, vec![1, 2], "the scan must find V1 and V2");

        // 3 With V2 disabled, only the V1 output is found.
        let versions = {
            let set = utxo_set.lock().await;
            set.scan_and_return_self_owned_lifts(&engine_key, &account_key, false)
                .iter()
                .map(Lift::lift_version)
                .collect::<Vec<_>>()
        };
        assert_eq!(versions, vec![1], "V1 scanning must be unaffected");

        // 4 A V2 output for another account is not self-owned.
        let other_script =
            return_liftv2_scriptpubkey(other_key, engine_key).expect("other v2 scriptpubkey");
        {
            let mut set = utxo_set.lock().await;
            set.insert_utxo(&outpoint(0x03), &txout(other_script, 300_000));
        }
        let owned = {
            let set = utxo_set.lock().await;
            set.scan_and_return_self_owned_lifts(&engine_key, &account_key, true)
        };
        assert_eq!(owned.len(), 2, "another account's V2 output must not match");
        assert!(owned.iter().all(|lift| lift.account_key() == account_key));
    }
}
