use crate::constructive::calldata::element::sbe::encode::error::encode_error::CalldataElementSBEEncodeError;
use crate::constructive::core_types::entities::account::root_account::registered_and_configured_root_account::ext::sync_with_registry::sync_with_registry_error::RegisteredAndConfiguredRootAccountSyncWithRegistryError;
use crate::constructive::core_types::entities::account::root_account::registered_but_unconfigured_root_account::ext::sync_with_registry::sync_with_registry_error::RegisteredButUnconfiguredRootAccountSyncWithRegistryError;
use crate::executive::vm::program_execution::exec_error::ExecutionError;
use crate::executive::vm::stack::stack_item::StackItem;
use crate::inscriptive::coin_manager::errors::balance_update_errors::CMAccountBalanceDownError;

/// Errors associated with executing a `Call` entry.
#[derive(Debug, Clone)]
pub enum CallExecutionError {
    /// The caller root account is not registered.
    UnexpectedUnregisteredRootAccountError,
    /// The caller root account's BLS key is not valid.
    RegisteredButUnconfiguredRootAccountValidateBLSKeyError,
    /// The caller root account's key authorization signature is not valid.
    RegisteredButUnconfiguredRootAccountInvalidAuthorizationSignatureError,
    /// Syncing the newly configured caller root account with the registry failed.
    RegisteredButUnconfiguredRootAccountSyncWithRegistryError(
        RegisteredButUnconfiguredRootAccountSyncWithRegistryError,
    ),
    /// Syncing the configured caller root account with the registry failed.
    RegisteredAndConfiguredRootAccountSyncWithRegistryError(
        RegisteredAndConfiguredRootAccountSyncWithRegistryError,
    ),
    /// The calldata size, which the entry fee depends on, could not be encoded.
    CalldataSBEEncodeError(CalldataElementSBEEncodeError),
    /// The entry fee does not fit the satoshi range.
    CallFeeOverflow,
    /// The caller could not be debited for the entry fee.
    CoinManagerAccountBalanceDownError(CMAccountBalanceDownError),
    /// The entry's ops price is not the execution's base ops price.
    BaseOpsPriceMismatchError {
        /// The base ops price the execution enforces.
        expected: u32,
        /// The ops price the entry declared.
        actual: u32,
    },
    /// The program execution failed.
    ExecutionError(ExecutionError),
    /// The method did not return exactly one item.
    InvalidStackEndingError(usize),
    /// The single returned item is not `true`.
    NonTrueReturnItemError(StackItem),
}
