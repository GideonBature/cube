use crate::constructive::core_types::entities::account::root_account::root_account::RootAccount;
use crate::constructive::entries::entry_fees::entry_fees::EntryFees;
use crate::constructive::entries::entry_kinds::call::call::Call;
use crate::executive::entry_executions::call_execution::error::call_execution_error::CallExecutionError;
use crate::executive::exec_ctx::exec_ctx::ExecCtx;
use crate::executive::vm::program_execution::caller::Caller;
use crate::executive::vm::program_execution::exec::execute;
use crate::executive::vm::stack::stack_item::StackItem;

/// The base ops price a call executes with.
///
/// Mirrors the placeholder used by `ExecCtx::execute_batch`. Freezing it here keeps the entry's
/// declared ops price and the executor's enforced price comparable; it must be replaced by a
/// params-manager value before any economic claim is made.
pub const BASE_OPS_PRICE: u32 = 100;

/// The parts-per-million denominator used by the calldata-size fee.
const PPM_DENOMINATOR: u64 = 1_000_000;

impl ExecCtx {
    /// Executes a `Call` entry.
    ///
    /// The transition has three parts, in this order:
    ///
    /// 1. authenticate and sync the caller root account with the registry,
    /// 2. debit the caller's entry fee,
    /// 3. execute the called method, which may itself move a payable value from the caller into
    ///    the contract.
    ///
    /// Every step mutates the ephemeral deltas. Atomicity is therefore the caller's obligation:
    /// `ExecCtx::pre_execution` must have been called before this function, and
    /// `ExecCtx::rollback_last` must be called when it returns `Err`. Both entry points that use
    /// this function do exactly that.
    ///
    /// Fee composition is deliberately minimal: `call_entry_base_fee` plus
    /// `call_entry_ppm_calldata_bytesize_fee` applied to the SBE-encoded calldata size. The
    /// `in_call_ppm_liquidity_fee` and the ops price are **not** charged, because no fee formula
    /// for them exists in the source. Charging them would silently change the caller's authorised
    /// debit and must be specified first.
    pub async fn execute_call_internal(
        &mut self,
        call: &Call,
        execution_timestamp: u64,
    ) -> Result<EntryFees, CallExecutionError> {
        // 1 Resolve the caller account key and the called contract id.
        let account_key = call.account.account_key();
        let contract_id = call.contract.contract_id();

        // 2 Authenticate the caller root account and sync it with the registry.
        match &call.account {
            RootAccount::UnregisteredRootAccount(_) => {
                return Err(CallExecutionError::UnexpectedUnregisteredRootAccountError);
            }
            RootAccount::RegisteredButUnconfiguredRootAccount(
                registered_but_unconfigured_root_account,
            ) => {
                // 2.a The account must present a valid BLS key and a valid key authorization.
                if !registered_but_unconfigured_root_account.validate_bls_key() {
                    return Err(
                        CallExecutionError::RegisteredButUnconfiguredRootAccountValidateBLSKeyError,
                    );
                }

                if !registered_but_unconfigured_root_account.verify_authorization_signature() {
                    return Err(
                        CallExecutionError::RegisteredButUnconfiguredRootAccountInvalidAuthorizationSignatureError,
                    );
                }

                // 2.b Configure the account and bump its call counter.
                registered_but_unconfigured_root_account
                    .sync_with_registry(execution_timestamp, &self.registry)
                    .await
                    .map_err(
                        CallExecutionError::RegisteredButUnconfiguredRootAccountSyncWithRegistryError,
                    )?;
            }
            RootAccount::RegisteredAndConfiguredRootAccount(
                registered_and_configured_root_account,
            ) => {
                // 2.c Already configured: only the counters need syncing.
                registered_and_configured_root_account
                    .sync_with_registry(execution_timestamp, &self.registry)
                    .await
                    .map_err(
                        CallExecutionError::RegisteredAndConfiguredRootAccountSyncWithRegistryError,
                    )?;
            }
        }

        // 3 Get the params holder snapshot.
        let params_holder = {
            let _params_manager = self._params_manager.lock().unwrap();
            _params_manager.get_params_holder()
        };

        // 4 Compute the calldata size the entry fee is based on.
        let mut calldata_bytes_len: u64 = 0;
        for calldata_element in call.calldata_elements().iter() {
            let encoded = calldata_element
                .encode_sbe()
                .map_err(CallExecutionError::CalldataSBEEncodeError)?;
            calldata_bytes_len = calldata_bytes_len
                .checked_add(encoded.len() as u64)
                .ok_or(CallExecutionError::CallFeeOverflow)?;
        }

        // 5 Compute the entry fee: a flat base plus a per-byte charge expressed in ppm.
        let base_fee = params_holder.call_entry_base_fee;
        let calldata_fee = (u128::from(calldata_bytes_len)
            * u128::from(params_holder.call_entry_ppm_calldata_bytesize_fee)
            / u128::from(PPM_DENOMINATOR)) as u64;
        let total_pre_subsidy = base_fee
            .checked_add(calldata_fee)
            .ok_or(CallExecutionError::CallFeeOverflow)?;

        // 6 Debit the entry fee before execution, so a method cannot run unpaid.
        {
            let mut _coin_manager = self.coin_manager.lock().await;
            _coin_manager
                .account_balance_down(account_key, total_pre_subsidy)
                .map_err(CallExecutionError::CoinManagerAccountBalanceDownError)?;
        }

        // 7 Reject an entry that declares a different ops price than the execution enforces.
        let ops_price = call.ops_price_total();
        if ops_price != BASE_OPS_PRICE {
            return Err(CallExecutionError::BaseOpsPriceMismatchError {
                expected: BASE_OPS_PRICE,
                actual: ops_price,
            });
        }

        // 8 Execute the called method through the runtime.
        let ops_budget = call.ops_budget().unwrap_or_default();
        let args_as_stack_items: Vec<StackItem> = call
            .calldata_elements()
            .iter()
            .map(|calldata_element| calldata_element.into_stack_item())
            .collect();

        let (return_items, _ops_spent, _external_ops_counter) = execute(
            false,
            Caller::new_account(account_key),
            contract_id,
            call.method_index(),
            args_as_stack_items,
            execution_timestamp,
            ops_budget,
            ops_price,
            0,
            0,
            params_holder,
            &self.state_manager,
            &self.coin_manager,
            &self.registry,
        )
        .await
        .map_err(CallExecutionError::ExecutionError)?;

        // 9 Require the method to return exactly one item, and that item to be true.
        if return_items.len() != 1 {
            return Err(CallExecutionError::InvalidStackEndingError(
                return_items.len(),
            ));
        }

        let return_item = return_items
            .into_iter()
            .next()
            .ok_or(CallExecutionError::InvalidStackEndingError(0))?;
        if !return_item.is_true() {
            return Err(CallExecutionError::NonTrueReturnItemError(return_item));
        }

        // 10 Return the recorded fees.
        Ok(EntryFees::Call {
            base_fee,
            total_pre_subsidy,
            subsidy_breakdown: None,
        })
    }
}
