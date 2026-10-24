//! Negative batch execution: a batch that fails *after* mutating the deltas must leave no trace.
//!
//! The happy path lives in `simul.rs`. This test builds the same single-liftup batch, corrupts one
//! byte of the aggregate BLS signature, and expects `execute_batch` to fail at the signature check
//! that runs after the entries have executed. The point is what happens next:
//!
//! - the coin manager must look exactly as it did before the attempt,
//! - and the same, uncorrupted container must still execute successfully afterwards, which it could
//!   not if the failed attempt had left the deltas half-applied.
//!
//! That is the regression the batch-level snapshot exists for.

#[cfg(test)]
mod batch_atomicity_tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
    use cube::constructive::bitcoiny::batch_container::batch_container::BatchContainer;
    use cube::constructive::core_types::entities::account::root_account::root_account::RootAccount;
    use cube::constructive::core_types::target::target::Target;
    use cube::constructive::entries::entry_kinds::liftup::liftup::Liftup;
    use cube::constructive::txo::lift::lift::Lift;
    use cube::constructive::txo::lift::lift_versions::liftv1::liftv1::return_liftv1_scriptpubkey;
    use cube::executive::exec_ctx::errors::batch_execution_error::BatchExecutionError;
    use cube::executive::exec_ctx::exec_ctx::ExecCtx;
    use cube::executive::exec_ctx::exec_ctx::EXEC_CTX;
    use cube::inscriptive::archival_manager::archival_manager::{
        erase_archival_manager, ArchivalManager, ARCHIVAL_MANAGER,
    };
    use cube::inscriptive::coin_manager::coin_manager::{
        erase_coin_manager, CoinManager, COIN_MANAGER,
    };
    use cube::inscriptive::flame_manager::flame_manager::{
        erase_flame_manager, FlameManager, FLAME_MANAGER,
    };
    use cube::inscriptive::graveyard::graveyard::{erase_graveyard, Graveyard, GRAVEYARD};
    use cube::inscriptive::params_manager::params_manager::{
        erase_params_manager, ParamsManager, PARAMS_MANAGER,
    };
    use cube::inscriptive::privileges_manager::privileges_manager::{
        erase_privileges_manager, PrivilegesManager, PRIVILEGES_MANAGER,
    };
    use cube::inscriptive::registry::registry::{erase_registry, Registry, REGISTRY};
    use cube::inscriptive::state_manager::state_manager::{
        erase_state_manager, StateManager, STATE_MANAGER,
    };
    use cube::inscriptive::sync_manager::sync_manager::{
        erase_sync_manager, SyncManager, SYNC_MANAGER,
    };
    use cube::inscriptive::utxo_set::utxo_set::{erase_utxo_set, UTXOSet, UTXO_SET};
    use cube::operative::run_args::chain::Chain;
    use cube::operative::tasks::engine_session::session_pool::session_pool::{
        SessionPool, SESSION_POOL,
    };
    use cube::transmutative::key::KeyHolder;
    use std::sync::Arc;

    /// The well-known testbed Engine key.
    const ENGINE_KEY: [u8; 32] = [
        0xa3, 0x08, 0xf8, 0x7d, 0x88, 0x7d, 0x78, 0x34, 0x19, 0xb8, 0x4b, 0x97, 0x65, 0x1f, 0xd8,
        0xa5, 0xf8, 0x8f, 0x6d, 0xb6, 0x41, 0x4a, 0xe6, 0xeb, 0x19, 0x84, 0xcc, 0x67, 0x42, 0xee,
        0xf0, 0x9e,
    ];

    /// The offset of the aggregate BLS signature inside the payload: version (u32) + timestamp
    /// (u64), then 96 signature bytes.
    const AGGREGATE_SIGNATURE_OFFSET: usize = 12;

    /// The engine context plus what the assertions need.
    struct Harness {
        exec_ctx: EXEC_CTX,
        coin_manager: COIN_MANAGER,
        batch_container: BatchContainer,
        account_key: [u8; 32],
    }

    /// Builds a session with one liftup entry and the batch container it produces.
    async fn harness() -> Harness {
        let (batch_height, timestamp, feerate) = (1, 1_776_015_147, 1);

        let secret_key: [u8; 32] =
            hex::decode("2795044ce0f83f718bc79c5f2add1e52521978df91ce9b7f82c9097191d33602")
                .expect("secret key hex")
                .try_into()
                .expect("secret key length");
        let key_holder = KeyHolder::new(secret_key).expect("key holder");
        let public_key = key_holder.secp_public_key_bytes();

        let chain = Chain::Testbed;
        erase_sync_manager(chain);
        erase_utxo_set(chain);
        erase_registry(chain);
        erase_graveyard(chain);
        erase_coin_manager(chain);
        erase_flame_manager(chain);
        erase_state_manager(chain);
        erase_privileges_manager(chain);
        erase_params_manager(chain);
        erase_archival_manager(chain);

        let sync_manager: SYNC_MANAGER = SyncManager::new(chain).expect("sync manager");
        let utxo_set: UTXO_SET = UTXOSet::new(chain).expect("utxo set");
        let registry: REGISTRY = Registry::new(chain).expect("registry");
        let graveyard: GRAVEYARD = Graveyard::new(chain).expect("graveyard");
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin manager");
        let flame_manager: FLAME_MANAGER = FlameManager::new(chain).expect("flame manager");
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state manager");
        let privileges_manager: PRIVILEGES_MANAGER =
            PrivilegesManager::new(chain).expect("privileges manager");
        let params_manager: PARAMS_MANAGER = ParamsManager::new(chain).expect("params manager");
        let archival_manager: ARCHIVAL_MANAGER =
            ArchivalManager::new(chain).expect("archival manager");

        // Fund a LiftV1 output and register it in the UTXO set.
        let lift: Lift = {
            let lift_scriptpubkey =
                return_liftv1_scriptpubkey(public_key, ENGINE_KEY).expect("lift scriptpubkey");
            let outpoint = OutPoint::new(Txid::from_byte_array([0x00u8; 32]), 0);
            let txout = TxOut {
                value: Amount::from_sat(25_000),
                script_pubkey: ScriptBuf::from(lift_scriptpubkey),
            };
            utxo_set.lock().await.insert_utxo(&outpoint, &txout);
            Lift::new_liftv1(public_key, ENGINE_KEY, outpoint, txout)
        };

        let liftup: Liftup = {
            let root_account =
                RootAccount::self_root_account_from_registry(&key_holder, &registry).await;
            let tip = sync_manager.lock().await.cube_batch_sync_height_tip();
            Liftup::new(root_account, Target::new(tip + 1), vec![lift])
        };
        let liftup_signature = liftup.bls_sign(&key_holder).expect("liftup signature");

        let session_pool: SESSION_POOL = SessionPool::construct(
            ENGINE_KEY,
            &Arc::clone(&sync_manager),
            &Arc::clone(&utxo_set),
            &Arc::clone(&registry),
            &Arc::clone(&graveyard),
            &Arc::clone(&coin_manager),
            &Arc::clone(&flame_manager),
            &Arc::clone(&state_manager),
            &Arc::clone(&privileges_manager),
            &Arc::clone(&params_manager),
            Some(Arc::clone(&archival_manager)),
        );

        {
            let mut pool = session_pool.lock().await;
            pool.begin_session(batch_height, timestamp, feerate);
        }

        session_pool
            .lock()
            .await
            .exec_liftup_in_pool(&liftup, liftup_signature)
            .await
            .expect("the liftup must be admitted");

        let batch_container = session_pool
            .lock()
            .await
            .into_batch_container(&key_holder)
            .await
            .expect("the container must build");

        session_pool.lock().await.end_session().await;
        drop(session_pool);

        let exec_ctx: EXEC_CTX = ExecCtx::construct(
            ENGINE_KEY,
            Arc::clone(&sync_manager),
            Arc::clone(&utxo_set),
            Arc::clone(&registry),
            Arc::clone(&graveyard),
            Arc::clone(&coin_manager),
            Arc::clone(&flame_manager),
            Arc::clone(&state_manager),
            Arc::clone(&privileges_manager),
            Arc::clone(&params_manager),
            None,
        );

        Harness {
            exec_ctx,
            coin_manager,
            batch_container,
            account_key: public_key,
        }
    }

    /// Returns the account balance as the coin manager currently sees it, delta included.
    async fn balance(coin_manager: &COIN_MANAGER, account_key: [u8; 32]) -> Option<u64> {
        coin_manager.lock().await.get_account_balance(account_key)
    }

    #[tokio::test]
    async fn a_failed_batch_leaves_no_delta_and_the_retry_still_works() {
        let harness = harness().await;
        let before = balance(&harness.coin_manager, harness.account_key).await;

        // 1 Corrupt one byte of the aggregate signature. Entry decoding is untouched, so the
        //   liftup executes and the failure happens at the check that follows it.
        let mut corrupted_bytes = harness.batch_container.new_payload_bytes.clone();
        corrupted_bytes[AGGREGATE_SIGNATURE_OFFSET] ^= 0x01;
        let corrupted = BatchContainer::new(
            harness.batch_container.batch_height,
            corrupted_bytes,
            harness.batch_container.signed_batch_txn.clone(),
        );

        let result = harness
            .exec_ctx
            .lock()
            .await
            .execute_batch(&corrupted)
            .await;
        match result {
            Err(BatchExecutionError::AggregateBLSSignatureVerificationError) => {}
            Err(other) => panic!("the batch must fail at the aggregate signature, got: {other:?}"),
            Ok(_) => panic!("the corrupted batch must not execute"),
        }

        // 2 The failed attempt must have rolled the deltas back: the coin manager's balance view is
        //   unchanged. A fresh account's credit is recorded as a pending registration rather than an
        //   updated balance, so this check alone would not catch a leak; step 3 is the decisive one.
        let after_failure = balance(&harness.coin_manager, harness.account_key).await;
        assert_eq!(
            after_failure, before,
            "a failed batch must not leave a balance update behind"
        );

        // 3 The same context must still be able to execute the honest batch. Without the rollback
        //   this fails with `AccountHasJustBeenEphemerallyRegistered`: the leaked registration from
        //   the failed attempt is still in the delta.
        harness
            .exec_ctx
            .lock()
            .await
            .execute_batch(&harness.batch_container)
            .await
            .expect("the honest batch must execute after the failed one");

        let after_success = balance(&harness.coin_manager, harness.account_key).await;
        assert_ne!(
            after_success, before,
            "the successful batch must change the balance, otherwise this test observes nothing"
        );
    }
}
