//! The deploy gate: a program that is not a reviewed template must not become a contract.
//!
//! The gate runs before any fee or registration side effect, and before the caller's account is
//! inspected. That ordering is what these tests exploit: an unregistered caller still reaches the
//! allowlist decision, so a rejection can be observed without a funded fixture.
//!
//! The positive case does not assert that the deploy succeeds — an unregistered caller cannot pay —
//! only that the reviewed template gets past the allowlist and fails later, for the account reason.

use cube::constructive::calldata::element_type::CalldataElementType;
use cube::constructive::contracts::fixed_split_vault_v1;
use cube::constructive::core_types::entities::account::root_account::root_account::RootAccount;
use cube::constructive::core_types::target::target::Target;
use cube::constructive::entries::entry_kinds::deploy::deploy::Deploy;
use cube::executive::entry_executions::deploy_execution::error::deploy_execution_error::DeployExecutionError;
use cube::executive::exec_ctx::exec_ctx::{ExecCtx, EXEC_CTX};
use cube::executive::executable::executable::{Executable, Program};
use cube::executive::executable::method::method_type::MethodType;
use cube::executive::executable::method::program_method::ProgramMethod;
use cube::executive::opcode::opcode::Opcode;
use cube::executive::opcode::opcodes::flow::op_nop::OP_NOP;
use cube::executive::opcode::opcodes::flow::op_returnall::OP_RETURNALL;
use cube::executive::opcode::opcodes::push::op_true::OP_TRUE;
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
use cube::transmutative::key::KeyHolder;
use std::sync::Arc;

/// A valid secp256k1 secret for the deploying account.
const DEPLOYER_SECRET_KEY: [u8; 32] = [
    0xbc, 0xee, 0xf6, 0x55, 0xb5, 0xa0, 0x34, 0x91, 0x1f, 0x1c, 0x37, 0x18, 0xce, 0x05, 0x66, 0x31,
    0xb4, 0x5e, 0xf0, 0x3b, 0x4c, 0x7b, 0x1f, 0x15, 0x62, 0x9e, 0x86, 0x72, 0x94, 0x01, 0x1a, 0x7d,
];

/// The well-known testbed Engine key.
const ENGINE_KEY: [u8; 32] = [
    0xa3, 0x08, 0xf8, 0x7d, 0x88, 0x7d, 0x78, 0x34, 0x19, 0xb8, 0x4b, 0x97, 0x65, 0x1f, 0xd8, 0xa5,
    0xf8, 0x8f, 0x6d, 0xb6, 0x41, 0x4a, 0xe6, 0xeb, 0x19, 0x84, 0xcc, 0x67, 0x42, 0xee, 0xf0, 0x9e,
];

/// The timestamp every fixture uses.
const TIMESTAMP: u64 = 1_700_000_000;

/// A program that is deliberately not the reviewed template.
fn unreviewed_program() -> Program {
    let method = ProgramMethod::new(
        "noop".to_string(),
        MethodType::Callable,
        Vec::<CalldataElementType>::new(),
        vec![
            Opcode::OP_TRUE(OP_TRUE),
            Opcode::OP_NOP(OP_NOP),
            Opcode::OP_NOP(OP_NOP),
            Opcode::OP_RETURNALL(OP_RETURNALL),
        ],
    )
    .expect("the fixture method must construct");

    Executable::new("unreviewed_fixture".to_string(), None, vec![method])
        .expect("the fixture program must construct")
}

/// Builds a fresh engine context and the unregistered caller that submits the deploys.
async fn harness() -> (EXEC_CTX, RootAccount) {
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
    let _archival_manager: ARCHIVAL_MANAGER =
        ArchivalManager::new(chain).expect("archival manager");

    let key_holder = KeyHolder::new(DEPLOYER_SECRET_KEY).expect("key holder");
    let root_account = RootAccount::self_root_account_from_registry(&key_holder, &registry).await;

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

    (exec_ctx, root_account)
}

/// Runs both scenarios sequentially: they share one on-disk test database, which cannot be opened
/// twice at once.
#[tokio::test]
async fn the_deploy_gate_admits_only_reviewed_templates() {
    // 1 An unreviewed program is refused by the allowlist, before any side effect.
    {
        let (exec_ctx, root_account) = harness().await;
        let program = unreviewed_program();
        let expected_hash = program.contract_id();
        let deploy = Deploy::new(root_account, program, 0, Target::new(1));

        let result = exec_ctx
            .lock()
            .await
            .execute_deploy(&deploy, TIMESTAMP)
            .await;
        match result {
            Err(DeployExecutionError::TemplateNotAllowlistedError { template_hash }) => {
                assert_eq!(template_hash, expected_hash);
            }
            Err(other) => {
                panic!("the unreviewed program must be refused by the allowlist, got: {other:?}")
            }
            Ok(_) => panic!("an unreviewed program must not be deployable"),
        }
    }

    // 2 The reviewed template gets past the gate. It still cannot be deployed, because the caller
    //   is unregistered, but the allowlist is not what stops it.
    {
        let (exec_ctx, root_account) = harness().await;
        let deploy = Deploy::new(
            root_account,
            fixed_split_vault_v1::template(),
            0,
            Target::new(1),
        );

        let result = exec_ctx
            .lock()
            .await
            .execute_deploy(&deploy, TIMESTAMP)
            .await;
        if let Err(DeployExecutionError::TemplateNotAllowlistedError { .. }) = result {
            panic!("the reviewed template must not be refused by the allowlist");
        }
    }
}
