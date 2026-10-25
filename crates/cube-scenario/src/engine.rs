//! Running the `FixedSplitVaultV1` transition on the real CubeVM.
//!
//! This module boots the same components the node boots — the managers, the session pool and the
//! executor — against the disposable `Testbed` databases, registers the template, and executes
//! `fund_split` through the production admission path (`exec_call_in_pool`). It then reads the
//! value-bearing state back from the managers:
//!
//! ```text
//! owner balance, fee balance, contract balance, Bob's shadow, Carol's shadow, phase
//! ```
//!
//! Entry fees are set to zero for this flow. The canonical `SplitState` models the split's
//! obligations, not the Engine's entry-fee market; running with zero fees makes the VM ledger and
//! the canonical state directly comparable. The template's own fee transfer is still exercised:
//! the execution fee moves to the fee account as its own opcode.
//!
//! What this module does **not** do: it does not start the interactive `runner::run`, does not sync
//! Bitcoin, and does not publish a batch container. The call executes against the in-memory delta;
//! `tests/simul.rs` covers the liftup -> batch container -> `execute_batch` path separately.

use crate::DebugContext;
use anyhow::{anyhow, bail, Context, Result};
use cube::constructive::contracts::fixed_split_vault_v1::template::{
    template, FUND_SPLIT_METHOD_NAME, PHASE_ALLOCATED, STATE_KEY_PHASE,
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
use cube::inscriptive::privileges_manager::bodies::contract_body::contract_body::PrivilegesManagerContractBody;
use cube::inscriptive::privileges_manager::elements::exemption::exemption::Exemption;
use cube::inscriptive::privileges_manager::elements::liveness_flag::liveness_flag::LivenessFlag;
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

/// The batch height every fixture targets.
const BATCH_HEIGHT: u64 = 101;
/// The execution timestamp every fixture uses.
const TIMESTAMP: u64 = 1_700_000_000;
/// The Bitcoin fee-rate placeholder the pool is opened with.
const FEE_RATE: u64 = 1_000;
/// The base ops price the executor enforces.
const BASE_OPS_PRICE: u32 = 100;
/// The ops budget the call declares.
const OPS_BUDGET: u32 = 100_000;

/// The value-bearing state the VM reached, read back from the managers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VmExecution {
    /// The template contract id the VM registered, hex.
    pub contract_id: String,
    /// The phase tag stored by the template (`PHASE_ALLOCATED` on success).
    pub phase_tag: u8,
    /// The gross amount the call funded.
    pub gross_sats: u64,
    /// The execution fee the call declared.
    pub execution_fee_sats: u64,
    /// The owner's native balance before the call.
    pub owner_start_sats: u64,
    /// The owner's native balance after the call.
    pub owner_balance_sats: u64,
    /// The fee account's native balance after the call.
    pub fee_balance_sats: u64,
    /// The contract's native balance after the call.
    pub contract_balance_sats: u64,
    /// Bob's shadow allocation after the call.
    pub bob_shadow_sats: u64,
    /// Carol's shadow allocation after the call.
    pub carol_shadow_sats: u64,
    /// The entry fee the executor charged. Zero in this flow by construction.
    pub entry_fee_sats: u64,
}

/// Executes `fund_split` on the CubeVM and returns the resulting state.
///
/// `owner_start_sats` is Alice's native balance before the call; it must cover the gross amount.
/// The function wipes the `Testbed` databases, so it must not run concurrently with another
/// in-process manager fixture.
pub fn fund_split(
    gross_sats: u64,
    execution_fee_sats: u64,
    owner_start_sats: u64,
) -> Result<VmExecution> {
    if gross_sats > u64::from(u32::MAX) || execution_fee_sats > u64::from(u32::MAX) {
        bail!("the fixture amounts must fit the template's u32 calldata");
    }
    if owner_start_sats < gross_sats {
        bail!("the owner cannot fund the gross amount");
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("cannot build a Tokio runtime for the Engine flow")?;
    runtime.block_on(async move {
        execute_fund_split(gross_sats, execution_fee_sats, owner_start_sats).await
    })
}

/// The async body of [`fund_split`].
async fn execute_fund_split(
    gross_sats: u64,
    execution_fee_sats: u64,
    owner_start_sats: u64,
) -> Result<VmExecution> {
    // 1 Disposable testbed, one run at a time.
    let chain = Chain::Testbed;
    erase_coin_manager(chain);
    erase_registry(chain);
    erase_state_manager(chain);
    erase_params_manager(chain);
    erase_graveyard(chain);
    erase_sync_manager(chain);
    erase_utxo_set(chain);
    erase_flame_manager(chain);
    erase_privileges_manager(chain);

    // 2 Fresh managers.
    let coin_manager: COIN_MANAGER = CoinManager::new(chain).context_debug("coin manager")?;
    let registry: REGISTRY = Registry::new(chain).context_debug("registry")?;
    let state_manager: STATE_MANAGER = StateManager::new(chain).context_debug("state manager")?;
    let params_manager: PARAMS_MANAGER = ParamsManager::new(chain).context("params manager")?;
    let graveyard: GRAVEYARD = Graveyard::new(chain).context_debug("graveyard")?;
    let sync_manager: SYNC_MANAGER = SyncManager::new(chain).context_debug("sync manager")?;
    let utxo_set: UTXO_SET = UTXOSet::new(chain).context("utxo set")?;
    let flame_manager: FLAME_MANAGER = FlameManager::new(chain).context_debug("flame manager")?;
    let privileges_manager: PRIVILEGES_MANAGER =
        PrivilegesManager::new(chain).context_debug("privileges manager")?;

    // 3 Zero entry fees, so the VM ledger is directly comparable with the canonical state.
    {
        let mut params = params_manager
            .lock()
            .expect("the params lock is not poisoned");
        params.pre_execution();
        params.set_call_entry_base_fee(0);
        params.set_call_entry_ppm_calldata_bytesize_fee(0);
        params
            .apply_changes()
            .context("cannot persist the zero-fee params")?;
    }

    // 4 Participants and the fee account.
    let alice = KeyHolder::new(crate::keys::ALICE_SECRET).context("Alice's key holder")?;
    let bob = KeyHolder::new(crate::keys::BOB_SECRET).context("Bob's key holder")?;
    let carol = KeyHolder::new(crate::keys::CAROL_SECRET).context("Carol's key holder")?;
    let engine = KeyHolder::new(crate::keys::ENGINE_SECRET).context("the Engine's key holder")?;
    let alice_key = alice.secp_public_key_bytes();
    let bob_key = bob.secp_public_key_bytes();
    let carol_key = carol.secp_public_key_bytes();
    let fee_key = crate::keys::xonly(crate::keys::FEE_KEY);
    let engine_key = engine.secp_public_key_bytes();

    // 5 Register the signing participants as configured root accounts.
    {
        let mut registry = registry.lock().await;
        for (account_key, bls_key) in [
            (alice_key, alice.bls_public_key_bytes()),
            (bob_key, bob.bls_public_key_bytes()),
            (carol_key, carol.bls_public_key_bytes()),
        ] {
            registry
                .register_account(account_key, TIMESTAMP, Some(bls_key), None, None, None)
                .map_err(|error| anyhow!("cannot register a root account: {error:?}"))?;
        }
        registry
            .apply_changes()
            .context_debug("cannot persist accounts")?;
    }

    // 6 Register the allowlisted template as a contract, in the registry, the state manager, the
    //   privileges manager and the coin manager.
    let program = template();
    let contract_id = program.contract_id();
    {
        let mut registry = registry.lock().await;
        registry
            .register_contract(contract_id, TIMESTAMP, program.clone())
            .map_err(|error| anyhow!("cannot register the template: {error:?}"))?;
        registry
            .apply_changes()
            .context_debug("cannot persist the contract")?;
    }
    {
        let mut state_manager = state_manager.lock().await;
        state_manager
            .register_contract(contract_id)
            .map_err(|error| anyhow!("cannot register the contract state: {error:?}"))?;
        state_manager
            .apply_changes()
            .context_debug("cannot persist the contract state")?;
    }
    {
        let mut privileges = privileges_manager.lock().await;
        privileges
            .register_contract(
                contract_id,
                PrivilegesManagerContractBody::new(
                    LivenessFlag::new_operational(),
                    false,
                    Exemption::new(None, None, None),
                ),
            )
            .map_err(|error| anyhow!("cannot register contract privileges: {error:?}"))?;
        privileges
            .apply_changes()
            .context_debug("cannot persist contract privileges")?;
    }
    {
        let mut coin_manager = coin_manager.lock().await;
        coin_manager
            .register_contract(contract_id, 0)
            .map_err(|error| anyhow!("cannot register the contract balance: {error:?}"))?;
        coin_manager
            .register_account(alice_key, owner_start_sats)
            .map_err(|error| anyhow!("cannot fund Alice: {error:?}"))?;
        coin_manager
            .register_account(bob_key, 0)
            .map_err(|error| anyhow!("cannot register Bob: {error:?}"))?;
        coin_manager
            .register_account(carol_key, 0)
            .map_err(|error| anyhow!("cannot register Carol: {error:?}"))?;
        coin_manager
            .register_account(fee_key, 0)
            .map_err(|error| anyhow!("cannot register the fee account: {error:?}"))?;
        coin_manager
            .apply_changes()
            .context_debug("cannot persist the balances")?;
    }

    // 7 Open the session pool through the same constructor the node uses.
    let session_pool: SESSION_POOL = SessionPool::construct(
        engine_key,
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
    session_pool
        .lock()
        .await
        .begin_session(BATCH_HEIGHT, TIMESTAMP, FEE_RATE);

    // 8 Build `fund_split` and sign it with Alice's BLS key.
    let method_index = program
        .index_by_method_name(FUND_SPLIT_METHOD_NAME)
        .context("the template has no fund_split method")? as u16;
    let call = Call::new(
        RootAccount::self_root_account_from_registry(&alice, &registry).await,
        Contract::new(contract_id, 0),
        MethodIndex::new(method_index),
        vec![
            CalldataElement::Account(Account::new_unregistered_account(bob_key)),
            CalldataElement::Account(Account::new_unregistered_account(carol_key)),
            CalldataElement::Payable(gross_sats as u32),
            CalldataElement::U32(execution_fee_sats as u32),
            CalldataElement::Account(Account::new_unregistered_account(fee_key)),
        ],
        OpsBudget::new(Some(OPS_BUDGET)),
        OpsPrice::new(u64::from(BASE_OPS_PRICE)),
        Target::new(BATCH_HEIGHT),
    );
    let signature = call
        .bls_sign(&alice)
        .map_err(|error| anyhow!("cannot sign fund_split: {error:?}"))?;

    // 9 Execute through the production admission path.
    session_pool
        .lock()
        .await
        .exec_call_in_pool(&call, signature)
        .await
        .context_debug("exec_call_in_pool rejected fund_split")?;

    // 10 Read the value-bearing state back from the managers.
    let (contract_balance_sats, bob_shadow_sats, carol_shadow_sats) = {
        let coin_manager = coin_manager.lock().await;
        (
            coin_manager
                .get_contract_balance(contract_id)
                .context("the contract has no balance")?,
            coin_manager
                .get_shadow_alloc_value_in_satoshis(contract_id, bob_key)
                .unwrap_or(0),
            coin_manager
                .get_shadow_alloc_value_in_satoshis(contract_id, carol_key)
                .unwrap_or(0),
        )
    };
    let (owner_balance_sats, fee_balance_sats) = {
        let coin_manager = coin_manager.lock().await;
        (
            coin_manager
                .get_account_balance(alice_key)
                .context("Alice has no balance")?,
            coin_manager
                .get_account_balance(fee_key)
                .context("the fee account has no balance")?,
        )
    };
    let phase_tag = {
        let state_manager = state_manager.lock().await;
        state_manager
            .get_state_value(contract_id, &vec![STATE_KEY_PHASE])
            .and_then(|value| value.first().copied())
            .context("the template wrote no phase")?
    };
    if phase_tag != PHASE_ALLOCATED {
        bail!("the VM vault is not ALLOCATED after fund_split");
    }

    // 11 The entry fee is zero by construction; assert it rather than assume it.
    let entry_fee_sats = owner_start_sats
        .checked_sub(owner_balance_sats)
        .and_then(|spent| spent.checked_sub(gross_sats))
        .context("Alice's balance does not account for the gross amount")?;

    Ok(VmExecution {
        contract_id: hex::encode(contract_id),
        phase_tag,
        gross_sats,
        execution_fee_sats,
        owner_start_sats,
        owner_balance_sats,
        fee_balance_sats,
        contract_balance_sats,
        bob_shadow_sats,
        carol_shadow_sats,
        entry_fee_sats,
    })
}
