use crate::constructive::entity::account::root_account::ext::validate_root_account::validate_root_account_error::RootAccountValidateRootAccountError;

/// Errors from [`Call::validate_overall`].
#[derive(Debug, Clone)]
pub enum CallValidateOverallError {
    /// The caller root account is not registered, so it has no key material to authorise a call.
    UnregisteredRootAccountNotAllowedError,
    /// The caller root account failed its own key/authorization validation.
    ValidateRootAccountError(RootAccountValidateRootAccountError),
    /// The target lies outside the accepted batch window.
    ValidateTargetError {
        targeted_at_batch_height: u64,
        execution_batch_height: u64,
    },
    /// The called contract is not registered.
    ContractNotFoundError([u8; 32]),
    /// The method index does not exist in the contract's method table.
    MethodNotFoundError {
        contract_id: [u8; 32],
        method_index: u16,
        methods_len: usize,
    },
    /// The call does not declare an ops budget.
    MissingOpsBudgetError,
}
