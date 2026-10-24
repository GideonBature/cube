//! End-to-end tests for the authorised `Call` entry path.
//!
//! Until this change, `Entry::Call` had no executor: `ExecCtx::execute_batch` refused it and the
//! session pool had no `exec_call_in_pool`. These tests drive the full admission path —
//! BLS signature verification, end-to-end pre-validation, execution against backed-up manager
//! deltas, and rollback on failure — so the wiring lands with evidence rather than ahead of it.
//!
//! Covered here:
//!
//! - a validly signed call executes, charges its entry fee and moves its payable value,
//! - a call signed by the wrong key is rejected before anything moves,
//! - a call whose method fails leaves the fee and the payable value rolled back,
//! - a caller that cannot pay the fee is rejected,
//! - a target outside the batch window is rejected,
//! - a call to an unknown contract is rejected.
//!
//! Not covered here: `Entry::Call` reaching `ExecCtx::execute_batch` from a decoded APE payload.
//! That arm shares `execute_call_internal` with this path, but a batch-level fixture is a separate
//! piece of harness work.

#[cfg(test)]
mod call_entry_tests {
    use cube::constructive::calldata::element_type::CalldataElementType;
    use cube::constructive::core_types::calldata::calldata_elements::calldata_element::CalldataElement;
    use cube::constructive::core_types::entities::account::root_account::root_account::RootAccount;
    use cube::constructive::core_types::entities::contract::contract::Contract;
    use cube::constructive::core_types::method_index::method_index::MethodIndex;
    use cube::constructive::core_types::ops_budget::ops_budget::OpsBudget;
    use cube::constructive::core_types::ops_price::ops_price::OpsPrice;
    use cube::constructive::core_types::target::target::Target;
    use cube::constructive::entries::entry_kinds::call::call::Call;
    use cube::executive::executable::executable::Executable;
    use cube::executive::executable::method::method_type::MethodType;
    use cube::executive::executable::method::program_method::ProgramMethod;
    use cube::executive::opcode::opcode::Opcode;
    use cube::executive::opcode::opcodes::flow::op_fail::OP_FAIL;
    use cube::executive::opcode::opcodes::flow::op_nop::OP_NOP;
    use cube::executive::opcode::opcodes::flow::op_returnall::OP_RETURNALL;
    use cube::executive::opcode::opcodes::push::op_true::OP_TRUE;
    use cube::executive::opcode::opcodes::stack::op_drop::OP_DROP;
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

    /// A valid secp256k1 secret key for the calling account.
    const ACCOUNT_SECRET_KEY: [u8; 32] = [
        0xbc, 0xee, 0xf6, 0x55, 0xb5, 0xa0, 0x34, 0x91, 0x1f, 0x1c, 0x37, 0x18, 0xce, 0x05, 0x66,
        0x31, 0xb4, 0x5e, 0xf0, 0x3b, 0x4c, 0x7b, 0x1f, 0x15, 0x62, 0x9e, 0x86, 0x72, 0x94, 0x01,
        0x1a, 0x7d,
    ];

    /// A different valid secret key, used to produce a signature by the wrong account.
    const IMPOSTOR_SECRET_KEY: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x03,
    ];

    /// The well-known testbed Engine key.
    const ENGINE_KEY: [u8; 32] = [
        0xa3, 0x08, 0xf8, 0x7d, 0x88, 0x7d, 0x78, 0x34, 0x19, 0xb8, 0x4b, 0x97, 0x65, 0x1f, 0xd8,
        0xa5, 0xf8, 0x8f, 0x6d, 0xb6, 0x41, 0x4a, 0xe6, 0xeb, 0x19, 0x84, 0xcc, 0x67, 0x42, 0xee,
        0xf0, 0x9e,
    ];

    /// The batch height every fixture targets.
    const BATCH_HEIGHT: u64 = 101;

    /// The execution timestamp every fixture uses.
    const TIMESTAMP: u64 = 1_700_000_000;

    /// The Bitcoin transaction fee rate placeholder the pool is opened with.
    const FEE_RATE: u64 = 1_000;

    /// The base ops price the executor enforces.
    const BASE_OPS_PRICE: u32 = 100;

    /// The ops budget every fixture call declares.
    const OPS_BUDGET: u32 = 100_000;

    /// `call_entry_base_fee` in the origin params holder.
    const BASE_FEE: u64 = 10;

    /// Builds the test program: a payable no-op and a payable method that fails.
    fn build_program() -> Executable {
        // 1 `pay_noop`: [payable] -> drop -> true -> nop -> return all.
        let pay_noop = ProgramMethod::new(
            "pay_noop".to_string(),
            MethodType::Callable,
            vec![CalldataElementType::Payable],
            vec![
                Opcode::OP_DROP(OP_DROP),
                Opcode::OP_TRUE(OP_TRUE),
                Opcode::OP_NOP(OP_NOP),
                Opcode::OP_RETURNALL(OP_RETURNALL),
            ],
        )
        .expect("pay_noop must construct");

        // 2 `pay_fail`: [payable] -> drop -> fail.
        let pay_fail = ProgramMethod::new(
            "pay_fail".to_string(),
            MethodType::Callable,
            vec![CalldataElementType::Payable],
            vec![
                Opcode::OP_DROP(OP_DROP),
                Opcode::OP_FAIL(OP_FAIL),
                Opcode::OP_TRUE(OP_TRUE),
                Opcode::OP_RETURNALL(OP_RETURNALL),
            ],
        )
        .expect("pay_fail must construct");

        Executable::new(
            "call_entry_fixture".to_string(),
            None,
            vec![pay_noop, pay_fail],
        )
        .expect("program must construct")
    }

    /// Every manager a `SessionPool` needs, plus the registered program.
    struct Harness {
        session_pool: SESSION_POOL,
        coin_manager: COIN_MANAGER,
        contract_id: [u8; 32],
        program: Executable,
        key_holder: KeyHolder,
        account_key: [u8; 32],
    }

    /// Erases the test databases and registers the caller account and the program.
    async fn harness(account_balance_sats: u64, contract_balance_sats: u64) -> Harness {
        // 1 Use a disposable chain for the test databases.
        let chain = Chain::Testbed;

        // 2 Erase the previous run of this binary.
        erase_coin_manager(chain);
        erase_registry(chain);
        erase_state_manager(chain);
        erase_params_manager(chain);
        erase_graveyard(chain);
        erase_sync_manager(chain);
        erase_utxo_set(chain);
        erase_flame_manager(chain);
        erase_privileges_manager(chain);

        // 3 Construct fresh managers.
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin manager");
        let registry: REGISTRY = Registry::new(chain).expect("registry");
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state manager");
        let params_manager: PARAMS_MANAGER = ParamsManager::new(chain).expect("params manager");
        let graveyard: GRAVEYARD = Graveyard::new(chain).expect("graveyard");
        let sync_manager: SYNC_MANAGER = SyncManager::new(chain).expect("sync manager");
        let utxo_set: UTXO_SET = UTXOSet::new(chain).expect("utxo set");
        let flame_manager: FLAME_MANAGER = FlameManager::new(chain).expect("flame manager");
        let privileges_manager: PRIVILEGES_MANAGER =
            PrivilegesManager::new(chain).expect("privileges manager");

        // 4 Derive the caller's keys.
        let key_holder = KeyHolder::new(ACCOUNT_SECRET_KEY).expect("key holder");
        let account_key = key_holder.secp_public_key_bytes();
        let bls_key = key_holder.bls_public_key_bytes();

        // 5 Register the caller with its BLS key so it is a configured root account.
        {
            let mut _registry = registry.lock().await;
            _registry
                .register_account(account_key, TIMESTAMP, Some(bls_key), None, None, None)
                .expect("register account");
            _registry.apply_changes().expect("apply registry changes");
        }

        // 6 Register the program as a contract and give it an initial balance.
        let program = build_program();
        let contract_id = program.contract_id();
        {
            let mut _registry = registry.lock().await;
            _registry
                .register_contract(contract_id, TIMESTAMP, program.clone())
                .expect("register contract");
            _registry.apply_changes().expect("apply registry changes");
        }
        {
            let mut _state_manager = state_manager.lock().await;
            _state_manager
                .register_contract(contract_id)
                .expect("register contract state");
            _state_manager
                .apply_changes()
                .expect("apply state manager changes");
        }
        {
            let mut _privileges_manager = privileges_manager.lock().await;
            _privileges_manager
                .register_contract(
                    contract_id,
                    cube::inscriptive::privileges_manager::bodies::contract_body::contract_body::PrivilegesManagerContractBody::new(
                        cube::inscriptive::privileges_manager::elements::liveness_flag::liveness_flag::LivenessFlag::new_operational(),
                        false,
                        cube::inscriptive::privileges_manager::elements::exemption::exemption::Exemption::new(None, None, None),
                    ),
                )
                .expect("register contract privileges");
            _privileges_manager
                .apply_changes()
                .expect("apply privileges changes");
        }
        {
            let mut _coin_manager = coin_manager.lock().await;
            _coin_manager
                .register_contract(contract_id, contract_balance_sats)
                .expect("register contract balance");
            _coin_manager
                .register_account(account_key, account_balance_sats)
                .expect("register account balance");
            _coin_manager
                .apply_changes()
                .expect("apply coin manager changes");
        }

        // 7 Construct and open the session pool.
        let session_pool: SESSION_POOL = SessionPool::construct(
            ENGINE_KEY,
            &sync_manager,
            &utxo_set,
            &registry,
            &graveyard,
            &coin_manager,
            &flame_manager,
            &state_manager,
            &privileges_manager,
            &params_manager,
            None,
        );
        {
            let mut _session_pool = session_pool.lock().await;
            _session_pool.begin_session(BATCH_HEIGHT, TIMESTAMP, FEE_RATE);
        }

        // 8 Return the harness.
        Harness {
            session_pool,
            coin_manager,
            contract_id,
            program,
            key_holder,
            account_key,
        }
    }

    impl Harness {
        /// Returns the method index of a named method.
        fn method_index(&self, name: &str) -> u16 {
            self.program.index_by_method_name(name).expect("method") as u16
        }

        /// Builds a `Call` signed by the fixture account.
        async fn signed_call(&self, method_name: &str, payable_sats: u32) -> (Call, [u8; 96]) {
            let signed_call = self
                .unsigned_call(method_name, payable_sats, Target::new(BATCH_HEIGHT))
                .await;
            let signature = signed_call
                .bls_sign(&self.key_holder)
                .expect("the fixture call must sign");
            (signed_call, signature)
        }

        /// Builds an unsigned `Call` against the fixture contract.
        async fn unsigned_call(
            &self,
            method_name: &str,
            payable_sats: u32,
            target: Target,
        ) -> Call {
            Call::new(
                self.root_account().await,
                Contract::new(self.contract_id, 0),
                MethodIndex::new(self.method_index(method_name)),
                vec![CalldataElement::Payable(payable_sats)],
                OpsBudget::new(Some(OPS_BUDGET)),
                OpsPrice::new(u64::from(BASE_OPS_PRICE)),
                target,
            )
        }

        /// Resolves the caller's root account from the registry.
        async fn root_account(&self) -> RootAccount {
            // The registry is reachable through the pool; lock it briefly.
            let registry = { self.session_pool.lock().await.registry.clone() };
            RootAccount::self_root_account_from_registry(&self.key_holder, &registry).await
        }

        /// Returns the caller's current native balance.
        async fn caller_balance(&self) -> u64 {
            let _coin_manager = self.coin_manager.lock().await;
            _coin_manager
                .get_account_balance(self.account_key)
                .expect("caller must be registered")
        }

        /// Returns the contract's current native balance.
        async fn contract_balance(&self) -> u64 {
            let _coin_manager = self.coin_manager.lock().await;
            _coin_manager
                .get_contract_balance(self.contract_id)
                .expect("contract must be registered")
        }
    }

    // ---------------------------------------------------------------------------------------
    // Scenarios
    // ---------------------------------------------------------------------------------------

    /// The scenarios share one on-disk `sled` database, so they run in order through one driver
    /// test. Each scenario owns and drops its own harness so the next one can erase the database.
    #[tokio::test]
    async fn call_entry_tests() {
        call_entry_executes_and_charges_its_fee().await;
        call_entry_rejects_a_signature_by_another_key().await;
        call_entry_rolls_back_when_the_method_fails().await;
        call_entry_rejects_a_caller_that_cannot_pay().await;
        call_entry_rejects_a_stale_target().await;
        call_entry_rejects_an_unknown_contract().await;
    }

    async fn call_entry_executes_and_charges_its_fee() {
        let harness = harness(100_000, 0).await;
        let (call, signature) = harness.signed_call("pay_noop", 50_000).await;

        let (entry_id, entry, batch_height, _timestamp) = harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&call, signature)
            .await
            .expect("a validly signed call must execute");

        // 1 The entry is admitted with a derived identifier and a known kind.
        assert_ne!(entry_id, [0u8; 32]);
        assert_eq!(batch_height, BATCH_HEIGHT);
        assert!(matches!(
            entry,
            cube::constructive::entry::entry::entry::Entry::Call(_)
        ));

        // 2 The entry fee is `call_entry_base_fee` plus the per-byte charge on the 5-byte
        //   `Payable` calldata: 10 + floor(5 * 1_000_000 / 1_000_000) = 15 sats.
        let expected_fee = BASE_FEE + 5;

        // 3 The caller paid exactly the fee plus the authorised payable value.
        assert_eq!(
            harness.caller_balance().await,
            100_000 - expected_fee - 50_000
        );
        assert_eq!(harness.contract_balance().await, 50_000);
    }

    async fn call_entry_rejects_a_signature_by_another_key() {
        let harness = harness(100_000, 0).await;
        let (call, _) = harness.signed_call("pay_noop", 50_000).await;

        // Sign the same payload with a different account's key.
        let impostor = KeyHolder::new(IMPOSTOR_SECRET_KEY).expect("impostor key holder");
        let wrong_signature = call.bls_sign(&impostor).expect("signing must not fail");

        let result = harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&call, wrong_signature)
            .await;

        // The BLS check rejects it before any balance is touched.
        assert!(
            matches!(
                result,
                Err(cube::operative::tasks::engine_session::session_pool::error::exec_call_in_pool_error::ExecCallInPoolError::CallBLSVerifyError(_))
            ),
            "unexpected result: {:?}",
            result.err()
        );
        assert_eq!(harness.caller_balance().await, 100_000);
        assert_eq!(harness.contract_balance().await, 0);
    }

    async fn call_entry_rolls_back_when_the_method_fails() {
        let harness = harness(100_000, 0).await;
        let (call, signature) = harness.signed_call("pay_fail", 50_000).await;

        let result = harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&call, signature)
            .await;

        // The failure comes from execution, after the fee debit and the payable movement.
        assert!(
            matches!(
                result,
                Err(cube::operative::tasks::engine_session::session_pool::error::exec_call_in_pool_error::ExecCallInPoolError::CallExecutionError(_))
            ),
            "unexpected result: {:?}",
            result.err()
        );

        // Both the fee and the payable value were rolled back together.
        assert_eq!(harness.caller_balance().await, 100_000);
        assert_eq!(harness.contract_balance().await, 0);
    }

    async fn call_entry_rejects_a_caller_that_cannot_pay() {
        let harness = harness(0, 0).await;
        let (call, signature) = harness.signed_call("pay_noop", 50_000).await;

        let result = harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&call, signature)
            .await;

        assert!(
            matches!(
                result,
                Err(cube::operative::tasks::engine_session::session_pool::error::exec_call_in_pool_error::ExecCallInPoolError::CallExecutionError(_))
            ),
            "unexpected result: {:?}",
            result.err()
        );
        assert_eq!(harness.caller_balance().await, 0);
        assert_eq!(harness.contract_balance().await, 0);
    }

    async fn call_entry_rejects_a_stale_target() {
        let harness = harness(100_000, 0).await;

        // Target five batches before the execution height; the accepted window is four.
        let target = Target::new(BATCH_HEIGHT - 5);
        let call = harness.unsigned_call("pay_noop", 50_000, target).await;
        let signature = call.bls_sign(&harness.key_holder).expect("signing");

        let result = harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&call, signature)
            .await;

        assert!(
            matches!(
                result,
                Err(cube::operative::tasks::engine_session::session_pool::error::exec_call_in_pool_error::ExecCallInPoolError::CallValidateOverallError(_))
            ),
            "unexpected result: {:?}",
            result.err()
        );
        assert_eq!(harness.caller_balance().await, 100_000);
    }

    async fn call_entry_rejects_an_unknown_contract() {
        let harness = harness(100_000, 0).await;

        // Point the call at a contract that was never registered.
        let unknown_contract_id = [0x5au8; 32];
        let mut call = harness
            .unsigned_call("pay_noop", 50_000, Target::new(BATCH_HEIGHT))
            .await;
        call.contract = Contract::new(unknown_contract_id, 0);
        let signature = call.bls_sign(&harness.key_holder).expect("signing");

        let result = harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&call, signature)
            .await;

        assert!(
            matches!(
                result,
                Err(cube::operative::tasks::engine_session::session_pool::error::exec_call_in_pool_error::ExecCallInPoolError::CallValidateOverallError(_))
            ),
            "unexpected result: {:?}",
            result.err()
        );
        assert_eq!(harness.caller_balance().await, 100_000);
    }
}
