//! A crash inside the multi-store batch commit must be recoverable on restart.
//!
//! The commit applies six Sled databases that cannot share a transaction. The journal records the
//! batch before the first manager changes, and `reconcile_pending_commit` replays the archived
//! history from height one when a pending intent survives.
//!
//! This test builds two real liftup batches, executes them cleanly to get a reference state, then
//! repeats the run with an injected fault after the coin manager applied. It drops every store
//! handle (the crash), reopens, reconciles, and compares the recovered managers byte-for-byte with
//! the reference state. A second assertion proves the node refuses to execute another batch while a
//! commit is unreconciled.

#[cfg(test)]
mod commit_recovery_tests {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, Txid};
    use cube::constructive::bitcoiny::batch_container::batch_container::BatchContainer;
    use cube::constructive::core_types::entities::account::root_account::root_account::RootAccount;
    use cube::constructive::core_types::target::target::Target;
    use cube::constructive::entries::entry_kinds::liftup::liftup::Liftup;
    use cube::constructive::txo::lift::lift::Lift;
    use cube::constructive::txo::lift::lift_versions::liftv1::liftv1::return_liftv1_scriptpubkey;
    use cube::executive::exec_ctx::exec_ctx::{ExecCtx, APPLY_CHANGES_FAILPOINT, EXEC_CTX};
    use cube::inscriptive::archival_manager::archival_manager::{
        erase_archival_manager, ArchivalManager, ARCHIVAL_MANAGER,
    };
    use cube::inscriptive::coin_manager::coin_manager::{
        erase_coin_manager, CoinManager, COIN_MANAGER,
    };
    use cube::inscriptive::commit_journal::commit_journal::{erase_commit_journal, CommitJournal};
    use cube::inscriptive::commit_journal::reconcile::{reconcile_pending_commit, Reconciliation};
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
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    /// Both tests use the same testbed storage, so they must not run concurrently.
    static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// The well-known testbed Engine key.
    const ENGINE_KEY: [u8; 32] = [
        0xa3, 0x08, 0xf8, 0x7d, 0x88, 0x7d, 0x78, 0x34, 0x19, 0xb8, 0x4b, 0x97, 0x65, 0x1f, 0xd8,
        0xa5, 0xf8, 0x8f, 0x6d, 0xb6, 0x41, 0x4a, 0xe6, 0xeb, 0x19, 0x84, 0xcc, 0x67, 0x42, 0xee,
        0xf0, 0x9e,
    ];

    /// The two batch timestamps.
    const TIMESTAMP_1: u64 = 1_776_015_147;
    const TIMESTAMP_2: u64 = 1_776_015_157;

    /// The account secret used by the fixture.
    const ACCOUNT_SECRET_HEX: &str =
        "2795044ce0f83f718bc79c5f2add1e52521978df91ce9b7f82c9097191d33602";

    /// All stores a batch commit touches.
    struct Stores {
        sync_manager: SYNC_MANAGER,
        utxo_set: UTXO_SET,
        registry: REGISTRY,
        graveyard: GRAVEYARD,
        coin_manager: COIN_MANAGER,
        flame_manager: FLAME_MANAGER,
        state_manager: STATE_MANAGER,
        privileges_manager: PRIVILEGES_MANAGER,
        params_manager: PARAMS_MANAGER,
        archival_manager: ARCHIVAL_MANAGER,
    }

    /// The manager views compared between the clean run and the recovered run.
    #[derive(Debug, Clone, PartialEq)]
    struct Snapshot {
        account_balance: Option<u64>,
        cube_batch_tip: u64,
        archived_heights: Vec<u64>,
        coin: serde_json::Value,
        registry: serde_json::Value,
        state: serde_json::Value,
        flame: serde_json::Value,
        graveyard: serde_json::Value,
    }

    /// Erases every store and reconstructs it empty.
    fn fresh_stores(chain: Chain) -> Stores {
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
        erase_commit_journal(chain);

        Stores {
            sync_manager: SyncManager::new(chain).expect("sync manager"),
            utxo_set: UTXOSet::new(chain).expect("utxo set"),
            registry: Registry::new(chain).expect("registry"),
            graveyard: Graveyard::new(chain).expect("graveyard"),
            coin_manager: CoinManager::new(chain).expect("coin manager"),
            flame_manager: FlameManager::new(chain).expect("flame manager"),
            state_manager: StateManager::new(chain).expect("state manager"),
            privileges_manager: PrivilegesManager::new(chain).expect("privileges manager"),
            params_manager: ParamsManager::new(chain).expect("params manager"),
            archival_manager: ArchivalManager::new(chain).expect("archival manager"),
        }
    }

    /// Reads back the managers without changing them.
    async fn snapshot(stores: &Stores, account_key: [u8; 32]) -> Snapshot {
        let archived_heights = {
            let archival = stores.archival_manager.lock().await;
            (1..=4)
                .filter(|height| archival.batch_record_by_height(*height).is_some())
                .collect()
        };

        // Each guard must end before the next lock: a guard placed directly in a struct field
        // lives to the end of the whole literal and deadlocks the next acquisition.
        let account_balance = {
            stores
                .coin_manager
                .lock()
                .await
                .get_account_balance(account_key)
        };
        let cube_batch_tip = {
            stores
                .sync_manager
                .lock()
                .await
                .cube_batch_sync_height_tip()
        };
        let coin = { stores.coin_manager.lock().await.json() };
        let registry = { stores.registry.lock().await.json() };
        let state = { stores.state_manager.lock().await.json() };
        let flame = { stores.flame_manager.lock().await.json() };
        let graveyard = { stores.graveyard.lock().await.json() };

        Snapshot {
            account_balance,
            cube_batch_tip,
            archived_heights,
            coin,
            registry,
            state,
            flame,
            graveyard,
        }
    }

    /// Inserts one funded lift into the utxo set.
    async fn insert_lift(stores: &Stores, account_key: [u8; 32], seed: u8, sats: u64) -> Lift {
        let script = return_liftv1_scriptpubkey(account_key, ENGINE_KEY).expect("lift script");
        let outpoint = OutPoint::new(Txid::from_byte_array([seed; 32]), 0);
        let txout = TxOut {
            value: Amount::from_sat(sats),
            script_pubkey: ScriptBuf::from(script),
        };
        stores.utxo_set.lock().await.insert_utxo(&outpoint, &txout);
        Lift::new_liftv1(account_key, ENGINE_KEY, outpoint, txout)
    }

    /// Builds one batch container for a session of one liftup.
    async fn build_container(
        stores: &Stores,
        key_holder: &KeyHolder,
        height: u64,
        timestamp: u64,
        lift: Lift,
    ) -> BatchContainer {
        let root_account =
            RootAccount::self_root_account_from_registry(key_holder, &stores.registry).await;
        let liftup = Liftup::new(root_account, Target::new(height), vec![lift]);
        let signature = liftup.bls_sign(key_holder).expect("liftup signature");

        let session_pool: SESSION_POOL = SessionPool::construct(
            ENGINE_KEY,
            &Arc::clone(&stores.sync_manager),
            &Arc::clone(&stores.utxo_set),
            &Arc::clone(&stores.registry),
            &Arc::clone(&stores.graveyard),
            &Arc::clone(&stores.coin_manager),
            &Arc::clone(&stores.flame_manager),
            &Arc::clone(&stores.state_manager),
            &Arc::clone(&stores.privileges_manager),
            &Arc::clone(&stores.params_manager),
            Some(Arc::clone(&stores.archival_manager)),
        );

        {
            let mut pool = session_pool.lock().await;
            pool.begin_session(height, timestamp, 1);
        }
        session_pool
            .lock()
            .await
            .exec_liftup_in_pool(&liftup, signature)
            .await
            .expect("the liftup must be admitted");
        let container = session_pool
            .lock()
            .await
            .into_batch_container(key_holder)
            .await
            .expect("the container must build");
        session_pool.lock().await.end_session().await;

        container
    }

    /// Builds the two containers once, on a throwaway storage, and returns them.
    ///
    /// Container two needs the payload tip that container one creates, so batch one is executed
    /// before the second container is built. Both are self-contained and can be replayed later.
    async fn build_containers(chain: Chain) -> (BatchContainer, BatchContainer, [u8; 32]) {
        let secret: [u8; 32] = hex::decode(ACCOUNT_SECRET_HEX)
            .expect("secret hex")
            .try_into()
            .expect("secret length");
        let key_holder = KeyHolder::new(secret).expect("key holder");
        let account_key = key_holder.secp_public_key_bytes();

        let stores = fresh_stores(chain);
        let lift_1 = insert_lift(&stores, account_key, 0x01, 25_000).await;
        let lift_2 = insert_lift(&stores, account_key, 0x02, 35_000).await;

        let container_1 = build_container(&stores, &key_holder, 1, TIMESTAMP_1, lift_1).await;

        {
            let exec_ctx: EXEC_CTX = ExecCtx::construct(
                ENGINE_KEY,
                Arc::clone(&stores.sync_manager),
                Arc::clone(&stores.utxo_set),
                Arc::clone(&stores.registry),
                Arc::clone(&stores.graveyard),
                Arc::clone(&stores.coin_manager),
                Arc::clone(&stores.flame_manager),
                Arc::clone(&stores.state_manager),
                Arc::clone(&stores.privileges_manager),
                Arc::clone(&stores.params_manager),
                Some(Arc::clone(&stores.archival_manager)),
                None,
            );
            exec_ctx
                .lock()
                .await
                .execute_batch(&container_1)
                .await
                .expect("the fixture batch must execute");
        }

        let container_2 = build_container(&stores, &key_holder, 2, TIMESTAMP_2, lift_2).await;

        drop(stores);
        (container_1, container_2, account_key)
    }

    /// Executes both containers, optionally injecting a fault after one manager applied.
    async fn execute_two(
        chain: Chain,
        containers: (&BatchContainer, &BatchContainer),
        account_key: [u8; 32],
        fail_after: Option<u8>,
    ) -> Snapshot {
        let stores = fresh_stores(chain);
        let journal = CommitJournal::open(chain).expect("journal");

        // 0 The liftup decoder resolves each spent outpoint from the utxo set.
        let _lift_1 = insert_lift(&stores, account_key, 0x01, 25_000).await;
        let _lift_2 = insert_lift(&stores, account_key, 0x02, 35_000).await;

        let exec_ctx: EXEC_CTX = ExecCtx::construct(
            ENGINE_KEY,
            Arc::clone(&stores.sync_manager),
            Arc::clone(&stores.utxo_set),
            Arc::clone(&stores.registry),
            Arc::clone(&stores.graveyard),
            Arc::clone(&stores.coin_manager),
            Arc::clone(&stores.flame_manager),
            Arc::clone(&stores.state_manager),
            Arc::clone(&stores.privileges_manager),
            Arc::clone(&stores.params_manager),
            Some(Arc::clone(&stores.archival_manager)),
            Some(journal.clone()),
        );

        // 1 The first batch commits normally.
        exec_ctx
            .lock()
            .await
            .execute_batch(containers.0)
            .await
            .expect("batch one must execute");

        // 2 The second batch either commits or stops inside `apply_changes`.
        if let Some(step) = fail_after {
            APPLY_CHANGES_FAILPOINT.store(step, Ordering::Relaxed);
        }
        let second = exec_ctx.lock().await.execute_batch(containers.1).await;
        APPLY_CHANGES_FAILPOINT.store(0, Ordering::Relaxed);

        match fail_after {
            Some(step) => {
                let error = match second {
                    Err(error) => error,
                    Ok(_) => panic!("the injected fault must fail the batch"),
                };
                assert!(
                    format!("{error:?}").contains(&format!("InjectedFault({step})")),
                    "the batch must fail at the injected point, got: {error:?}"
                );
                // The intent must survive for the next process.
                let pending = journal.pending().expect("journal read").expect("pending");
                assert_eq!(pending.height, 2);
            }
            None => {
                second.expect("batch two must execute");
            }
        }
        drop(exec_ctx);
        drop(stores);

        // Read the state the way a restart sees it: the in-memory bookkeeping of the live
        // managers (for example an empty flame set that has no disk keys) is not the durable
        // state that recovery has to reproduce.
        let reopened = fresh_stores_without_erasing(chain);
        let observed = snapshot(&reopened, account_key).await;
        drop(reopened);
        observed
    }

    #[tokio::test]
    async fn an_interrupted_commit_is_replayed_to_the_same_state() {
        let _guard = TEST_LOCK.lock().await;
        let chain = Chain::Testbed;
        let (container_1, container_2, account_key) = build_containers(chain).await;

        // 1 Reference state: both batches commit cleanly.
        let expected = execute_two(chain, (&container_1, &container_2), account_key, None).await;
        assert_eq!(expected.cube_batch_tip, 2);
        assert_eq!(expected.archived_heights, vec![1, 2]);
        assert!(expected.account_balance.unwrap_or(0) > 0);

        // 2 Crash after the coin manager applied: flame and coin committed, the rest did not.
        let _torn = execute_two(chain, (&container_1, &container_2), account_key, Some(2)).await;

        // 3 Restart: the pending intent is replayed from the archived history.
        let outcome = reconcile_pending_commit(chain, ENGINE_KEY)
            .await
            .expect("reconciliation must succeed");
        assert_eq!(
            outcome,
            Reconciliation::RolledForward {
                height: 2,
                replayed_batches: 2,
                archived_record_inserted: false,
            }
        );

        // 4 The recovered managers must equal the clean run.
        let stores = fresh_stores_without_erasing(chain);
        let recovered = snapshot(&stores, account_key).await;
        assert_eq!(recovered, expected, "replay must reproduce the clean state");
        drop(stores);

        // 5 The journal is closed: a second reconciliation is a no-op.
        let again = reconcile_pending_commit(chain, ENGINE_KEY)
            .await
            .expect("an empty journal must reconcile");
        assert_eq!(again, Reconciliation::NothingPending);
        let journal = CommitJournal::open(chain).expect("journal");
        assert!(journal.pending().expect("journal read").is_none());
        assert_eq!(journal.last_committed(), Some(2));
    }

    #[tokio::test]
    async fn a_pending_commit_blocks_another_batch() {
        let _guard = TEST_LOCK.lock().await;
        let chain = Chain::Testbed;
        let (container_1, container_2, account_key) = build_containers(chain).await;

        // 1 Leave batch two's commit torn.
        let _torn = execute_two(chain, (&container_1, &container_2), account_key, Some(2)).await;

        // 2 A new batch must be refused instead of applying on top of the torn commit.
        let stores = fresh_stores_without_erasing(chain);
        let journal = CommitJournal::open(chain).expect("journal");
        let exec_ctx: EXEC_CTX = ExecCtx::construct(
            ENGINE_KEY,
            Arc::clone(&stores.sync_manager),
            Arc::clone(&stores.utxo_set),
            Arc::clone(&stores.registry),
            Arc::clone(&stores.graveyard),
            Arc::clone(&stores.coin_manager),
            Arc::clone(&stores.flame_manager),
            Arc::clone(&stores.state_manager),
            Arc::clone(&stores.privileges_manager),
            Arc::clone(&stores.params_manager),
            Some(Arc::clone(&stores.archival_manager)),
            Some(journal),
        );
        let blocked = exec_ctx.lock().await.execute_batch(&container_1).await;
        let error = match blocked {
            Err(error) => error,
            Ok(_) => panic!("an unreconciled commit must block execution"),
        };
        assert!(
            format!("{error:?}").contains("UnreconciledCommit(2)"),
            "the error must name the pending height, got: {error:?}"
        );

        drop(exec_ctx);
        drop(stores);

        // 3 Clean up so the next test starts from an empty storage.
        let _ = reconcile_pending_commit(chain, ENGINE_KEY).await;
    }

    /// Opens the existing stores without erasing them, for the fail-stop test.
    fn fresh_stores_without_erasing(chain: Chain) -> Stores {
        Stores {
            sync_manager: SyncManager::new(chain).expect("sync manager"),
            utxo_set: UTXOSet::new(chain).expect("utxo set"),
            registry: Registry::new(chain).expect("registry"),
            graveyard: Graveyard::new(chain).expect("graveyard"),
            coin_manager: CoinManager::new(chain).expect("coin manager"),
            flame_manager: FlameManager::new(chain).expect("flame manager"),
            state_manager: StateManager::new(chain).expect("state manager"),
            privileges_manager: PrivilegesManager::new(chain).expect("privileges manager"),
            params_manager: ParamsManager::new(chain).expect("params manager"),
            archival_manager: ArchivalManager::new(chain).expect("archival manager"),
        }
    }
}
