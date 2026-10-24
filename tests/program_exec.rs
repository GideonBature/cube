//! Executable-call tests for the CubeVM, focused on payable value movement.
//!
//! These tests exist because the payable branch of `program_execution::exec::execute` was
//! previously inert: it computed an `payable_allocation_value`, carried a
//! `// TODO: CHECK ENOUGH BALANCE.` marker and never debited the caller, while `OP_TRANSFER`
//! already debited the contract balance. Any reachable payable call would therefore have been
//! able to spend value the contract never received.
//!
//! What is covered here:
//!
//! - a payable call debits the caller and credits the contract by exactly the authorised value,
//! - an insolvent caller is rejected before either balance moves,
//! - a below-minimum payable value is rejected,
//! - a non-payable call moves no value,
//! - a failing payable method leaves both balances untouched through `ProgramExecCtx`.
//!
//! What is *not* covered here: `Entry::Call` reaching `ExecCtx::execute_batch` or the Engine
//! session pool. Those dispatch arms are not wired yet and are refused deterministically.

#[cfg(test)]
mod program_exec_tests {
    use cube::constructive::core_types::calldata::calldata_elements::calldata_element::CalldataElement;
    use cube::constructive::core_types::entities::account::root_account::registered_and_configured_root_account::registered_and_configured_root_account::RegisteredAndConfiguredRootAccount;
    use cube::constructive::core_types::entities::account::root_account::root_account::RootAccount;
    use cube::constructive::core_types::entities::contract::contract::Contract;
    use cube::constructive::core_types::method_index::method_index::MethodIndex;
    use cube::constructive::core_types::ops_budget::ops_budget::OpsBudget;
    use cube::constructive::core_types::ops_price::ops_price::OpsPrice;
    use cube::constructive::core_types::target::target::Target;
    use cube::constructive::entries::entry_kinds::call::call::Call;
    use cube::constructive::calldata::element_type::CalldataElementType;
    use cube::executive::executable::executable::Executable;
    use cube::executive::executable::method::method_type::MethodType;
    use cube::executive::executable::method::program_method::ProgramMethod;
    use cube::executive::opcode::opcode::Opcode;
    use cube::executive::opcode::opcodes::flow::op_fail::OP_FAIL;
    use cube::executive::opcode::opcodes::flow::op_nop::OP_NOP;
    use cube::executive::opcode::opcodes::flow::op_returnall::OP_RETURNALL;
    use cube::executive::opcode::opcodes::push::op_true::OP_TRUE;
    use cube::executive::opcode::opcodes::stack::op_drop::OP_DROP;
    use cube::executive::vm::program_execution::caller::Caller;
    use cube::executive::vm::program_execution::exec::execute;
    use cube::executive::vm::program_execution::exec_error::ExecutionError;
    use cube::executive::vm::program_execution::program_exec_ctx::ProgramExecCtx;
    use cube::inscriptive::coin_manager::coin_manager::{erase_coin_manager, CoinManager, COIN_MANAGER};
    use cube::inscriptive::params_manager::params_manager::{
        erase_params_manager, ParamsManager, PARAMS_MANAGER,
    };
    use cube::inscriptive::registry::registry::{erase_registry, Registry, REGISTRY};
    use cube::inscriptive::state_manager::state_manager::{
        erase_state_manager, StateManager, STATE_MANAGER,
    };
    use cube::operative::run_args::chain::Chain;

    /// The account that funds payable calls in these fixtures.
    const CALLER_KEY: [u8; 32] = [
        0xfc, 0x7a, 0xca, 0xce, 0xf4, 0x50, 0x95, 0x60, 0x04, 0x27, 0xc6, 0x16, 0x87, 0x4a, 0x96,
        0xb7, 0x0e, 0x16, 0xcd, 0x2a, 0xb2, 0xa0, 0xea, 0x31, 0xa4, 0xa6, 0xae, 0x83, 0x4d, 0xbf,
        0x6f, 0x9d,
    ];

    /// A placeholder BLS key. Never validated on the execution path under test.
    const BLS_KEY: [u8; 48] = [0x22; 48];

    /// The base ops price the fixtures execute with.
    const BASE_OPS_PRICE: u32 = 100;

    /// The ops budget the fixtures execute with.
    const OPS_BUDGET: u32 = 100_000;

    /// The execution timestamp the fixtures execute with.
    const TIMESTAMP: u64 = 1_000;

    /// Builds the allowlisted-looking test program.
    ///
    /// Three callable methods:
    ///
    /// - `pay_noop`: takes a `Payable` arg, drops it, returns one `true` item.
    /// - `pay_fail`: takes a `Payable` arg, drops it, then fails.
    /// - `no_pay`: takes no args and returns one `true` item.
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

        // 3 `no_pay`: -> true -> nop -> true -> drop -> return all.
        let no_pay = ProgramMethod::new(
            "no_pay".to_string(),
            MethodType::Callable,
            vec![],
            vec![
                Opcode::OP_TRUE(OP_TRUE),
                Opcode::OP_NOP(OP_NOP),
                Opcode::OP_TRUE(OP_TRUE),
                Opcode::OP_DROP(OP_DROP),
                Opcode::OP_RETURNALL(OP_RETURNALL),
            ],
        )
        .expect("no_pay must construct");

        Executable::new(
            "program_exec_fixture".to_string(),
            None,
            vec![pay_noop, pay_fail, no_pay],
        )
        .expect("program must construct")
    }

    /// The managers and the registered program under test.
    struct Harness {
        coin_manager: COIN_MANAGER,
        registry: REGISTRY,
        state_manager: STATE_MANAGER,
        params_manager: PARAMS_MANAGER,
        program: Executable,
        contract_id: [u8; 32],
        registry_index: u64,
    }

    /// Erases the test databases and registers the program, a contract and the caller account.
    async fn harness(caller_balance_sats: u64, contract_balance_sats: u64) -> Harness {
        // 1 Use a disposable chain for the test databases.
        let chain = Chain::Testbed;

        // 2 Erase the previous run of this binary.
        erase_coin_manager(chain);
        erase_registry(chain);
        erase_state_manager(chain);
        erase_params_manager(chain);

        // 3 Construct fresh managers.
        let coin_manager: COIN_MANAGER = CoinManager::new(chain).expect("coin manager");
        let registry: REGISTRY = Registry::new(chain).expect("registry");
        let state_manager: STATE_MANAGER = StateManager::new(chain).expect("state manager");
        let params_manager: PARAMS_MANAGER = ParamsManager::new(chain).expect("params manager");

        // 4 Construct and register the program.
        let program = build_program();
        let contract_id = program.contract_id();

        {
            let mut _registry = registry.lock().await;
            _registry
                .register_contract(contract_id, TIMESTAMP, program.clone())
                .expect("register contract");
            _registry.apply_changes().expect("apply registry changes");
        }

        // 5 Register the contract balance and the caller account.
        {
            let mut _coin_manager = coin_manager.lock().await;
            _coin_manager
                .register_contract(contract_id, contract_balance_sats)
                .expect("register contract balance");
            _coin_manager
                .register_account(CALLER_KEY, caller_balance_sats)
                .expect("register caller account");
            _coin_manager
                .apply_changes()
                .expect("apply coin manager changes");
        }

        // 6 Return the harness.
        Harness {
            coin_manager,
            registry,
            state_manager,
            params_manager,
            program,
            contract_id,
            registry_index: 0,
        }
    }

    impl Harness {
        /// Returns the method index of a named method.
        fn method_index(&self, name: &str) -> u16 {
            self.program.index_by_method_name(name).expect("method") as u16
        }

        /// Executes one call directly through the VM entry point.
        async fn execute(
            &self,
            method_index: u16,
            args: Vec<CalldataElement>,
        ) -> Result<
            (
                Vec<cube::executive::vm::stack::stack_item::StackItem>,
                u32,
                u32,
            ),
            ExecutionError,
        > {
            let params_holder = {
                let _params_manager = self.params_manager.lock().unwrap();
                _params_manager.get_params_holder()
            };

            execute(
                false,
                Caller::new_account(CALLER_KEY),
                self.contract_id,
                method_index,
                args.iter().map(|arg| arg.into_stack_item()).collect(),
                TIMESTAMP,
                OPS_BUDGET,
                BASE_OPS_PRICE,
                0,
                0,
                params_holder,
                &self.state_manager,
                &self.coin_manager,
                &self.registry,
            )
            .await
        }

        /// Builds a `Call` entry for the `ProgramExecCtx` path.
        fn call(&self, method_index: u16, payable_sats: u32) -> Call {
            Call::new(
                RootAccount::RegisteredAndConfiguredRootAccount(
                    RegisteredAndConfiguredRootAccount::new(
                        CALLER_KEY,
                        self.registry_index,
                        BLS_KEY,
                    ),
                ),
                Contract::new(self.contract_id, self.registry_index),
                MethodIndex::new(method_index),
                vec![CalldataElement::Payable(payable_sats)],
                OpsBudget::new(Some(OPS_BUDGET)),
                OpsPrice::new(u64::from(BASE_OPS_PRICE)),
                Target::new(0),
            )
        }

        /// Returns the caller's current native balance.
        async fn caller_balance(&self) -> u64 {
            let _coin_manager = self.coin_manager.lock().await;
            _coin_manager
                .get_account_balance(CALLER_KEY)
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
    // Payable value movement
    // ---------------------------------------------------------------------------------------

    /// The scenarios share one on-disk `sled` database, so they must not run concurrently: a
    /// second open of the same database fails to acquire the lock. Every scenario therefore owns
    /// and drops its own harness, and one driver test runs them in order.
    #[tokio::test]
    async fn program_exec_tests() {
        payable_call_debits_the_caller_and_credits_the_contract().await;
        payable_call_rejects_an_insolvent_caller_without_moving_value().await;
        payable_call_rejects_a_below_minimum_allocation().await;
        non_payable_call_moves_no_value().await;
        failing_payable_call_rolls_the_value_back().await;
        successful_payable_call_is_recorded_and_keeps_the_value().await;
    }

    async fn payable_call_debits_the_caller_and_credits_the_contract() {
        let harness = harness(100_000, 0).await;
        let method_index = harness.method_index("pay_noop");

        // Execute a payable call for 50_000 sats.
        let result = harness
            .execute(method_index, vec![CalldataElement::Payable(50_000)])
            .await;
        assert!(result.is_ok(), "payable call failed: {:?}", result.err());

        // The value moved exactly once, from the caller to the contract.
        assert_eq!(harness.caller_balance().await, 50_000);
        assert_eq!(harness.contract_balance().await, 50_000);
    }

    async fn payable_call_rejects_an_insolvent_caller_without_moving_value() {
        let harness = harness(100, 0).await;
        let method_index = harness.method_index("pay_noop");

        let result = harness
            .execute(method_index, vec![CalldataElement::Payable(50_000)])
            .await;

        // The rejection names both sides so the caller can see why.
        match result {
            Err(ExecutionError::PayableCallerInsufficientFundsError {
                available_sats,
                required_sats,
            }) => {
                assert_eq!(available_sats, 100);
                assert_eq!(required_sats, 50_000);
            }
            other => panic!("unexpected result: {:?}", other),
        }

        // Nothing moved: the check happens before either balance is written.
        assert_eq!(harness.caller_balance().await, 100);
        assert_eq!(harness.contract_balance().await, 0);
    }

    async fn payable_call_rejects_a_below_minimum_allocation() {
        let harness = harness(100_000, 0).await;
        let method_index = harness.method_index("pay_noop");

        let result = harness
            .execute(method_index, vec![CalldataElement::Payable(9)])
            .await;

        assert!(
            matches!(result, Err(ExecutionError::MinPayableAllocationError)),
            "unexpected result: {:?}",
            result.err()
        );

        assert_eq!(harness.caller_balance().await, 100_000);
        assert_eq!(harness.contract_balance().await, 0);
    }

    async fn non_payable_call_moves_no_value() {
        let harness = harness(100_000, 0).await;
        let method_index = harness.method_index("no_pay");

        let result = harness.execute(method_index, vec![]).await;
        assert!(result.is_ok(), "plain call failed: {:?}", result.err());

        assert_eq!(harness.caller_balance().await, 100_000);
        assert_eq!(harness.contract_balance().await, 0);
    }

    // ---------------------------------------------------------------------------------------
    // Atomicity through `ProgramExecCtx`
    // ---------------------------------------------------------------------------------------

    async fn failing_payable_call_rolls_the_value_back() {
        let harness = harness(100_000, 0).await;
        let method_index = harness.method_index("pay_fail");

        let mut program_exec_ctx = ProgramExecCtx::new(
            &harness.state_manager,
            &harness.coin_manager,
            &harness.params_manager,
            &harness.registry,
            BASE_OPS_PRICE,
            TIMESTAMP,
        );

        let result = program_exec_ctx
            .exec_insert_call(harness.call(method_index, 50_000))
            .await;

        // The method failed...
        // The error must come from the method body, not from the payable step: a payable
        // rejection would leave the balances untouched for the wrong reason.
        match result {
            Err(ExecutionError::OpcodeExecutionError(_)) => {}
            other => panic!("expected an opcode failure, got: {:?}", other),
        }
        assert_eq!(program_exec_ctx.passed_calls_len(), 0);

        // ...and the payable debit and credit were rolled back together.
        assert_eq!(harness.caller_balance().await, 100_000);
        assert_eq!(harness.contract_balance().await, 0);
    }

    async fn successful_payable_call_is_recorded_and_keeps_the_value() {
        let harness = harness(100_000, 0).await;
        let method_index = harness.method_index("pay_noop");

        let mut program_exec_ctx = ProgramExecCtx::new(
            &harness.state_manager,
            &harness.coin_manager,
            &harness.params_manager,
            &harness.registry,
            BASE_OPS_PRICE,
            TIMESTAMP,
        );

        program_exec_ctx
            .exec_insert_call(harness.call(method_index, 50_000))
            .await
            .expect("payable call must succeed");

        // The call is recorded with the ops it spent.
        assert_eq!(program_exec_ctx.passed_calls_len(), 1);
        let passed_calls = program_exec_ctx.passed_calls();
        assert_eq!(passed_calls[0].0.method_index(), method_index);
        assert!(passed_calls[0].1 > 0, "the call must spend ops");
        assert_eq!(
            passed_calls[0].2,
            passed_calls[0].1 * BASE_OPS_PRICE,
            "fees are ops spent times the base ops price"
        );

        // And the value stayed where the call sent it.
        assert_eq!(harness.caller_balance().await, 50_000);
        assert_eq!(harness.contract_balance().await, 50_000);
    }
}
