//! Differential tests for the `FixedSplitVaultV1` template on the real CubeVM.
//!
//! The reference model in `cube::model::fixed_split_vault_v1` is the oracle: the same `G` and `E`
//! are applied to both, and the resulting contract balance and both shadow allocations must agree
//! exactly. This is the differential evidence implementation.md P3.3 asks for, exercised through
//! the production admission path (`exec_call_in_pool`) rather than a test-only shim.
//!
//! Covered here:
//!
//! - `fund_split` charges the fee as its own `OP_TRANSFER` and splits the remainder 70/30,
//! - the on-chain 70/30 split equals the reference model's arithmetic for the spec fixture,
//! - `redeem_share` converts one beneficiary's shadow allocation into native value,
//! - both beneficiaries can redeem, leaving the vault empty,
//! - a second redemption by the same beneficiary is rejected,
//! - a second funding of a live vault is rejected by the guard.
//!
//! Not covered here: the escrow pilot, proofs, Argo, or any Bitcoin enforcement. A redeeming
//! beneficiary is charged the normal entry fee, which the reference model does not model.

#[cfg(test)]
mod split_vault_template_tests {
    use cube::constructive::calldata::element_type::CalldataElementType;
    use cube::constructive::contracts::fixed_split_vault_v1::template::{
        template, template_bytes, template_hash, FUND_SPLIT_METHOD_NAME, REDEEM_SHARE_METHOD_NAME,
    };
    use cube::constructive::core_types::calldata::calldata_elements::calldata_element::CalldataElement;
    use cube::constructive::core_types::entities::account::account::account::Account;
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
    use cube::model::fixed_split_vault_v1::types::{Ledger, Role};
    use cube::model::fixed_split_vault_v1::{Auth, Operation, SplitDescriptor, SplitVault};
    use cube::operative::run_args::chain::Chain;
    use cube::operative::tasks::engine_session::session_pool::session_pool::{
        SessionPool, SESSION_POOL,
    };
    use cube::transmutative::key::KeyHolder;

    /// Alice's secret key.
    const ALICE_SECRET: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    /// Bob's secret key.
    const BOB_SECRET: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 2,
    ];

    /// Carol's secret key.
    const CAROL_SECRET: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 3,
    ];

    /// The fee account key. It only ever receives value, so it needs no BLS identity.
    const FEE_ACCOUNT_KEY: [u8; 32] = [0x44; 32];

    /// The well-known testbed Engine key.
    const ENGINE_KEY: [u8; 32] = [
        0xa3, 0x08, 0xf8, 0x7d, 0x88, 0x7d, 0x78, 0x34, 0x19, 0xb8, 0x4b, 0x97, 0x65, 0x1f, 0xd8,
        0xa5, 0xf8, 0x8f, 0x6d, 0xb6, 0x41, 0x4a, 0xe6, 0xeb, 0x19, 0x84, 0xcc, 0x67, 0x42, 0xee,
        0xf0, 0x9e,
    ];

    const BATCH_HEIGHT: u64 = 101;
    const TIMESTAMP: u64 = 1_700_000_000;
    const FEE_RATE: u64 = 1_000;
    const BASE_OPS_PRICE: u32 = 100;
    const OPS_BUDGET: u32 = 100_000;

    /// The spec's illustration: `G = 100000`, `E = 500`.
    const GROSS_SATS: u64 = 100_000;
    const EXECUTION_FEE_SATS: u32 = 500;

    /// `D`, and the expected fixed split.
    const DISTRIBUTABLE_SATS: u64 = 99_500;
    const EXPECTED_BOB_SATS: u64 = 69_650;
    const EXPECTED_CAROL_SATS: u64 = 29_850;

    /// Every participant starts with this much native value.
    const PARTICIPANT_START_SATS: u64 = 10_000;

    /// Alice's starting balance: enough for the payable value plus her entry fee.
    const ALICE_START_SATS: u64 = 200_000;

    /// The entry fee for a call whose SBE-encoded calldata is `bytes` long.
    ///
    /// `call_entry_base_fee` is 10 and `call_entry_ppm_calldata_bytesize_fee` is 1_000_000 ppm,
    /// which is one satoshi per byte.
    fn entry_fee(calldata_bytes: u64) -> u64 {
        10 + calldata_bytes
    }

    /// Returns the entry fee a call will actually be charged.
    ///
    /// Derived from the call's own SBE-encoded calldata rather than a hand-counted constant, so
    /// the assertion cannot drift from the encoder.
    fn entry_fee_for(call: &Call) -> u64 {
        let calldata_bytes: u64 = call
            .calldata_elements()
            .iter()
            .map(|element| element.encode_sbe().expect("calldata must encode").len() as u64)
            .sum();
        entry_fee(calldata_bytes)
    }

    /// A `SessionPool` plus the keys and identifiers the scenarios need.
    struct Harness {
        session_pool: SESSION_POOL,
        coin_manager: COIN_MANAGER,
        contract_id: [u8; 32],
        program: Executable,
        alice: KeyHolder,
        bob: KeyHolder,
        carol: KeyHolder,
        alice_key: [u8; 32],
        bob_key: [u8; 32],
        carol_key: [u8; 32],
    }

    /// Erases the databases, registers the participants and the template contract.
    async fn harness() -> Harness {
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

        // 4 Derive the participants' keys.
        let alice = KeyHolder::new(ALICE_SECRET).expect("alice key holder");
        let bob = KeyHolder::new(BOB_SECRET).expect("bob key holder");
        let carol = KeyHolder::new(CAROL_SECRET).expect("carol key holder");

        let alice_key = alice.secp_public_key_bytes();
        let bob_key = bob.secp_public_key_bytes();
        let carol_key = carol.secp_public_key_bytes();

        // 5 Register the three signing participants as configured root accounts.
        {
            let mut _registry = registry.lock().await;
            for (account_key, bls_key) in [
                (alice_key, alice.bls_public_key_bytes()),
                (bob_key, bob.bls_public_key_bytes()),
                (carol_key, carol.bls_public_key_bytes()),
            ] {
                _registry
                    .register_account(account_key, TIMESTAMP, Some(bls_key), None, None, None)
                    .expect("register account");
            }
            _registry.apply_changes().expect("apply registry changes");
        }

        // 6 Register the template as a contract.
        let program = template();
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

        // 7 Fund the accounts: the contract starts empty.
        {
            let mut _coin_manager = coin_manager.lock().await;
            _coin_manager
                .register_contract(contract_id, 0)
                .expect("register contract balance");
            _coin_manager
                .register_account(alice_key, ALICE_START_SATS)
                .expect("register alice");
            _coin_manager
                .register_account(bob_key, PARTICIPANT_START_SATS)
                .expect("register bob");
            _coin_manager
                .register_account(carol_key, PARTICIPANT_START_SATS)
                .expect("register carol");
            _coin_manager
                .register_account(FEE_ACCOUNT_KEY, 0)
                .expect("register fee account");
            _coin_manager
                .apply_changes()
                .expect("apply coin manager changes");
        }

        // 8 Construct and open the session pool.
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

        // 9 Return the harness.
        Harness {
            session_pool,
            coin_manager,
            contract_id,
            program,
            alice,
            bob,
            carol,
            alice_key,
            bob_key,
            carol_key,
        }
    }

    impl Harness {
        /// Returns the method index of a named template method.
        fn method_index(&self, name: &str) -> u16 {
            self.program.index_by_method_name(name).expect("method") as u16
        }

        /// Builds a `fund_split` call and signs it with Alice's key.
        async fn signed_fund_call(&self, gross_sats: u32) -> (Call, [u8; 96]) {
            let call = Call::new(
                self.root_account(&self.alice, self.alice_key).await,
                Contract::new(self.contract_id, 0),
                MethodIndex::new(self.method_index(FUND_SPLIT_METHOD_NAME)),
                vec![
                    CalldataElement::Account(self.account_of(self.bob_key)),
                    CalldataElement::Account(self.account_of(self.carol_key)),
                    CalldataElement::Payable(gross_sats),
                    CalldataElement::U32(EXECUTION_FEE_SATS),
                    CalldataElement::Account(self.account_of(FEE_ACCOUNT_KEY)),
                ],
                OpsBudget::new(Some(OPS_BUDGET)),
                OpsPrice::new(u64::from(BASE_OPS_PRICE)),
                Target::new(BATCH_HEIGHT),
            );
            let signature = call.bls_sign(&self.alice).expect("sign fund_split");
            (call, signature)
        }

        /// Builds a `redeem_share` call and signs it with the given participant's key.
        async fn signed_redeem_call(
            &self,
            key_holder: &KeyHolder,
            account_key: [u8; 32],
        ) -> (Call, [u8; 96]) {
            let call = Call::new(
                self.root_account(key_holder, account_key).await,
                Contract::new(self.contract_id, 0),
                MethodIndex::new(self.method_index(REDEEM_SHARE_METHOD_NAME)),
                vec![],
                OpsBudget::new(Some(OPS_BUDGET)),
                OpsPrice::new(u64::from(BASE_OPS_PRICE)),
                Target::new(BATCH_HEIGHT),
            );
            let signature = call.bls_sign(key_holder).expect("sign redeem_share");
            (call, signature)
        }

        /// Wraps a raw key in an `Account` calldata element.
        ///
        /// Only the key travels in the stack item, so the registration variant is irrelevant here.
        fn account_of(&self, key: [u8; 32]) -> Account {
            Account::new_unregistered_account(key)
        }

        /// Resolves a participant's root account from the registry.
        async fn root_account(
            &self,
            key_holder: &KeyHolder,
            _account_key: [u8; 32],
        ) -> RootAccount {
            let registry = { self.session_pool.lock().await.registry.clone() };
            RootAccount::self_root_account_from_registry(key_holder, &registry).await
        }

        /// Returns a native balance.
        async fn balance(&self, key: [u8; 32]) -> u64 {
            let _coin_manager = self.coin_manager.lock().await;
            _coin_manager
                .get_account_balance(key)
                .expect("account must be registered")
        }

        /// Returns the contract's native balance.
        async fn contract_balance(&self) -> u64 {
            let _coin_manager = self.coin_manager.lock().await;
            _coin_manager
                .get_contract_balance(self.contract_id)
                .expect("contract must be registered")
        }

        /// Returns a beneficiary's shadow allocation in the contract.
        async fn shadow(&self, key: [u8; 32]) -> u64 {
            let _coin_manager = self.coin_manager.lock().await;
            _coin_manager
                .get_shadow_alloc_value_in_satoshis(self.contract_id, key)
                .unwrap_or(0)
        }
    }

    /// The scenarios share one on-disk database, so they run in order through one driver test.
    #[tokio::test]
    async fn split_vault_template_tests() {
        template_is_stable_and_minimal().await;
        fund_split_matches_the_reference_model().await;
        both_beneficiaries_can_redeem().await;
        a_second_redemption_is_rejected().await;
        a_second_fund_of_a_live_vault_is_rejected().await;
    }

    /// The template compiles, keeps its shape, and both methods are callable.
    async fn template_is_stable_and_minimal() {
        let program = template();
        let bytes = template_bytes();

        // 1 The compiled bytecode is non-empty and the hash is derived from it.
        assert!(!bytes.is_empty());
        assert_eq!(template_hash(), program.contract_id());

        // 2 Both methods exist and are callable.
        assert_eq!(program.methods_len(), 2);
        for name in [FUND_SPLIT_METHOD_NAME, REDEEM_SHARE_METHOD_NAME] {
            let index = program.index_by_method_name(name).expect("method exists");
            let method: ProgramMethod = program
                .method_by_index(index as u16)
                .expect("method must be readable");
            assert_eq!(method.method_type(), MethodType::Callable);
        }

        // 3 `fund_split` declares exactly one payable argument and five arguments in total.
        let fund_index = program
            .index_by_method_name(FUND_SPLIT_METHOD_NAME)
            .expect("fund_split exists");
        let fund_method = program.method_by_index(fund_index as u16).expect("method");
        let arg_types = fund_method.arg_types();
        assert_eq!(arg_types.len(), 5);
        assert_eq!(
            arg_types
                .iter()
                .filter(|arg_type| **arg_type == CalldataElementType::Payable)
                .count(),
            1
        );
    }

    /// `fund_split` produces exactly the reference model's allocation.
    async fn fund_split_matches_the_reference_model() {
        let harness = harness().await;
        let (call, signature) = harness.signed_fund_call(GROSS_SATS as u32).await;

        harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&call, signature)
            .await
            .expect("fund_split must execute");

        // 1 The contract holds D and both shadows are exactly backed.
        assert_eq!(harness.contract_balance().await, DISTRIBUTABLE_SATS);
        assert_eq!(harness.shadow(harness.bob_key).await, EXPECTED_BOB_SATS);
        assert_eq!(harness.shadow(harness.carol_key).await, EXPECTED_CAROL_SATS);
        assert_eq!(
            harness.shadow(harness.bob_key).await + harness.shadow(harness.carol_key).await,
            harness.contract_balance().await,
            "the shadows must be exactly backed by the contract balance"
        );

        // 2 The fee account received the execution fee as its own transfer.
        assert_eq!(
            harness.balance(FEE_ACCOUNT_KEY).await,
            EXECUTION_FEE_SATS as u64
        );

        // 3 Alice paid the entry fee and the gross amount, nothing more.
        let expected_alice = ALICE_START_SATS - entry_fee_for(&call) - GROSS_SATS;
        assert_eq!(harness.balance(harness.alice_key).await, expected_alice);

        // 4 Differential check: the reference model derives the same vault state.
        let descriptor = SplitDescriptor::new(
            [0x11; 32],
            template_hash(),
            harness.alice_key,
            harness.bob_key,
            harness.carol_key,
            FEE_ACCOUNT_KEY,
        );
        let mut model = SplitVault::new(Ledger::new(ALICE_START_SATS, 0, 0, 0));
        model
            .instantiate(
                descriptor,
                Auth::new(Role::Owner, 1),
                Operation::new(
                    SplitVault::next_operation_id(1),
                    SplitVault::payload_digest(b"i"),
                ),
            )
            .expect("model instantiate");
        model
            .fund(
                GROSS_SATS,
                EXECUTION_FEE_SATS as u64,
                Auth::new(Role::Owner, 2),
                Operation::new(
                    SplitVault::next_operation_id(2),
                    SplitVault::payload_digest(b"f"),
                ),
            )
            .expect("model fund");

        let model_instance = model.instance.expect("model instance");
        assert_eq!(
            model_instance.contract_balance_sats,
            harness.contract_balance().await
        );
        assert_eq!(
            model_instance.bob_shadow_sats,
            harness.shadow(harness.bob_key).await
        );
        assert_eq!(
            model_instance.carol_shadow_sats,
            harness.shadow(harness.carol_key).await
        );
        assert!(model.check_invariants().is_ok());
    }

    /// Both beneficiaries redeem their allocation, in Bob-then-Carol order.
    async fn both_beneficiaries_can_redeem() {
        let harness = harness().await;

        // 1 Fund the vault.
        let (fund_call, fund_signature) = harness.signed_fund_call(GROSS_SATS as u32).await;
        harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&fund_call, fund_signature)
            .await
            .expect("fund_split must execute");

        // 2 Bob redeems his entire share.
        let (bob_call, bob_signature) = harness
            .signed_redeem_call(&harness.bob, harness.bob_key)
            .await;
        harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&bob_call, bob_signature)
            .await
            .expect("Bob's redemption must execute");

        assert_eq!(harness.shadow(harness.bob_key).await, 0);
        assert_eq!(harness.shadow(harness.carol_key).await, EXPECTED_CAROL_SATS);
        assert_eq!(harness.contract_balance().await, EXPECTED_CAROL_SATS);
        assert_eq!(
            harness.balance(harness.bob_key).await,
            PARTICIPANT_START_SATS - entry_fee(0) + EXPECTED_BOB_SATS
        );

        // 3 Carol redeems hers, leaving the vault empty.
        let (carol_call, carol_signature) = harness
            .signed_redeem_call(&harness.carol, harness.carol_key)
            .await;
        harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&carol_call, carol_signature)
            .await
            .expect("Carol's redemption must execute");

        assert_eq!(harness.shadow(harness.carol_key).await, 0);
        assert_eq!(harness.contract_balance().await, 0);
        assert_eq!(
            harness.balance(harness.carol_key).await,
            PARTICIPANT_START_SATS - entry_fee(0) + EXPECTED_CAROL_SATS
        );

        // 4 Physical value is conserved: the two payouts and the fee equal the gross.
        assert_eq!(
            harness.balance(harness.bob_key).await + harness.balance(harness.carol_key).await
                - (2 * (PARTICIPANT_START_SATS - entry_fee(0)))
                + harness.balance(FEE_ACCOUNT_KEY).await,
            GROSS_SATS
        );
    }

    /// Bob cannot redeem twice.
    async fn a_second_redemption_is_rejected() {
        let harness = harness().await;

        let (fund_call, fund_signature) = harness.signed_fund_call(GROSS_SATS as u32).await;
        harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&fund_call, fund_signature)
            .await
            .expect("fund_split must execute");

        let (bob_call, bob_signature) = harness
            .signed_redeem_call(&harness.bob, harness.bob_key)
            .await;
        harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&bob_call, bob_signature)
            .await
            .expect("Bob's first redemption must execute");

        let bob_after_first = harness.balance(harness.bob_key).await;
        let contract_after_first = harness.contract_balance().await;

        // The second attempt fails because the allocation is gone, not because of the signature.
        let (second_call, second_signature) = harness
            .signed_redeem_call(&harness.bob, harness.bob_key)
            .await;
        let result = harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&second_call, second_signature)
            .await;

        assert!(
            matches!(
                result,
                Err(cube::operative::tasks::engine_session::session_pool::error::exec_call_in_pool_error::ExecCallInPoolError::CallExecutionError(_))
            ),
            "unexpected result: {:?}",
            result.err()
        );

        // Nothing moved, including the entry fee.
        assert_eq!(harness.balance(harness.bob_key).await, bob_after_first);
        assert_eq!(harness.contract_balance().await, contract_after_first);
    }

    /// A live vault cannot be funded a second time, and each guard is exercised on its own.
    async fn a_second_fund_of_a_live_vault_is_rejected() {
        let harness = harness().await;

        let (fund_call, fund_signature) = harness.signed_fund_call(GROSS_SATS as u32).await;
        harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&fund_call, fund_signature)
            .await
            .expect("fund_split must execute");

        let contract_after_first = harness.contract_balance().await;
        let alice_after_first = harness.balance(harness.alice_key).await;

        // 1 The balance guard: a gross that does not match the contract balance is rejected
        //   before anything moves.
        let (mismatched_call, mismatched_signature) = harness.signed_fund_call(1_000).await;
        let result = harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&mismatched_call, mismatched_signature)
            .await;
        assert!(
            matches!(
                result,
                Err(cube::operative::tasks::engine_session::session_pool::error::exec_call_in_pool_error::ExecCallInPoolError::CallExecutionError(_))
            ),
            "unexpected result: {:?}",
            result.err()
        );

        // 2 The allocation guard: a gross that *does* match the contract balance still fails,
        //   because the vault already holds allocations.
        let (exact_call, exact_signature) =
            harness.signed_fund_call(contract_after_first as u32).await;
        let result = harness
            .session_pool
            .lock()
            .await
            .exec_call_in_pool(&exact_call, exact_signature)
            .await;
        assert!(
            matches!(
                result,
                Err(cube::operative::tasks::engine_session::session_pool::error::exec_call_in_pool_error::ExecCallInPoolError::CallExecutionError(_))
            ),
            "unexpected result: {:?}",
            result.err()
        );

        // 3 Neither attempt moved value, and the original allocation is untouched.
        assert_eq!(harness.contract_balance().await, contract_after_first);
        assert_eq!(harness.balance(harness.alice_key).await, alice_after_first);
        assert_eq!(harness.shadow(harness.bob_key).await, EXPECTED_BOB_SATS);
        assert_eq!(harness.shadow(harness.carol_key).await, EXPECTED_CAROL_SATS);
    }
}
