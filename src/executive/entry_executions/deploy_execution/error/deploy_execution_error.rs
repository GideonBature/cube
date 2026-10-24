use crate::constructive::entity::account::root_account::registered_and_configured_root_account::ext::sync_with_registry::sync_with_registry_error::RegisteredAndConfiguredRootAccountSyncWithRegistryError;
use crate::constructive::entity::account::root_account::registered_but_unconfigured_root_account::ext::sync_with_registry::sync_with_registry_error::RegisteredButUnconfiguredRootAccountSyncWithRegistryError;
use crate::executive::executable::program_error::MethodValidationError;
use crate::inscriptive::coin_manager::errors::balance_update_errors::CMAccountBalanceDownError;
use crate::inscriptive::coin_manager::errors::register_errors::CMRegisterContractError;
use crate::inscriptive::privileges_manager::errors::register_error::PMRegisterContractError;
use crate::inscriptive::registry::errors::register_contract_error::RMRegisterContractError;
use crate::inscriptive::state_manager::errors::register_error::SMRegisterContractError;

/// Errors associated with executing a `Deploy` entry.
#[derive(Debug, Clone)]
pub enum DeployExecutionError {
    UnexpectedUnregisteredRootAccountError,
    RegisteredButUnconfiguredRootAccountValidateBLSKeyError,
    RegisteredButUnconfiguredRootAccountInvalidAuthorizationSignatureError,
    RegisteredButUnconfiguredRootAccountSyncWithRegistryError(
        RegisteredButUnconfiguredRootAccountSyncWithRegistryError,
    ),
    RegisteredAndConfiguredRootAccountSyncWithRegistryError(
        RegisteredAndConfiguredRootAccountSyncWithRegistryError,
    ),
    ProgramValidateMethodsError(MethodValidationError),
    /// The compiled program is not a reviewed template, so it may not become a contract.
    TemplateNotAllowlistedError {
        /// The compiled identity of the program the deploy tried to register.
        template_hash: [u8; 32],
    },
    ProgramCompileError,
    DeployProgramByteFeeOverflow,
    DeployTotalPreSubsidyOverflow,
    DeployFeeDebitOverflow,
    FailedToApplyFeesSubsidy,
    CoinManagerAccountBalanceDownError(CMAccountBalanceDownError),
    RegistryRegisterContractError(RMRegisterContractError),
    CoinManagerRegisterContractError(CMRegisterContractError),
    StateManagerRegisterContractError(SMRegisterContractError),
    PrivilegesManagerRegisterContractError(PMRegisterContractError),
}
