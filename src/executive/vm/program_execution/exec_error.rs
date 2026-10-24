use crate::executive::stack::{stack_error::StackError, stack_item::StackItem};
use crate::inscriptive::coin_manager::errors::balance_update_errors::{
    CMAccountBalanceDownError, CMContractBalanceUpError,
};
use std::fmt;

/// A section of executable block in the `Contract`.
#[derive(Debug, Clone)]
pub enum ExecutionError {
    /// Executable not found error.
    ExecutableNotFoundError([u8; 32]),
    /// Method not found at index error.
    MethodNotFoundAtIndexError(u16),
    /// Read only call error.
    ReadOnlyCallEncounteredError,
    /// Internal call caller is not the contract error.
    InvalidInternalCallError,
    /// Invalid callable call error.
    InvalidCallableCallError,
    /// Stack holder initialization error.
    StackHolderInitializationError(StackError),
    /// Opcode execution error.
    OpcodeExecutionError(StackError),
    /// Method not returned any items error.
    MethodNotReturnedAnyItemsError,
    /// Invalid external call attempt as internal call error.
    ExternalCallAttemptAsInternalError,
    /// Return error item error.
    ReturnErrorFromStackError(StackItem),
    /// Arg type mismatch error.
    ArgTypeMismatchError,
    /// Min payable allocation error.
    MinPayableAllocationError,
    /// Payable allocation caller is not an account error.
    PayableAllocationCallerIsNotAnAccountError,
    /// Payable with internal call error.
    PayableWithInternalCallError,
    /// The payable caller is not a registered account.
    PayableCallerNotRegisteredError([u8; 32]),
    /// The payable caller does not hold the authorised value.
    PayableCallerInsufficientFundsError {
        /// Balance the caller actually held.
        available_sats: u64,
        /// Value the call authorised.
        required_sats: u64,
    },
    /// The payable destination contract is not registered with the coin manager.
    PayableContractNotRegisteredError([u8; 32]),
    /// The caller debit failed after the value was validated.
    PayableCallerBalanceDownError(CMAccountBalanceDownError),
    /// The contract credit failed after the caller was debited.
    PayableContractBalanceUpError(CMContractBalanceUpError),
    /// Invalid stack ending error.
    InvalidStackEndingError,
    /// Base ops price mismatch error.
    BaseOpsPriceMismatchError,
    /// Opcode index out of bounds error.
    OpcodeIndexOutOfBoundsError,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionError::ExecutableNotFoundError(contract_id) => {
                write!(f, "Executable not found at contract id: {:?}", contract_id)
            }
            ExecutionError::MethodNotFoundAtIndexError(index) => {
                write!(f, "Method not found at index: {}", index)
            }
            ExecutionError::ReadOnlyCallEncounteredError => {
                write!(f, "Read only call encountered")
            }
            ExecutionError::InvalidInternalCallError => {
                write!(f, "Invalid internal call")
            }
            ExecutionError::InvalidCallableCallError => {
                write!(f, "Invalid callable call")
            }
            ExecutionError::StackHolderInitializationError(error) => {
                write!(f, "Stack holder initialization error: {:?}", error)
            }
            ExecutionError::OpcodeExecutionError(error) => {
                write!(f, "Opcode execution error: {:?}", error)
            }
            ExecutionError::MethodNotReturnedAnyItemsError => {
                write!(f, "Method not returned any items")
            }
            ExecutionError::ExternalCallAttemptAsInternalError => {
                write!(f, "External call attempt as internal call")
            }
            ExecutionError::ReturnErrorFromStackError(error) => {
                write!(f, "Return error from stack: {:?}", error)
            }
            ExecutionError::ArgTypeMismatchError => {
                write!(f, "Arg type mismatch")
            }
            ExecutionError::MinPayableAllocationError => {
                write!(f, "Min payable   allocation error")
            }
            ExecutionError::PayableAllocationCallerIsNotAnAccountError => {
                write!(f, "Payable allocation caller is not an account")
            }
            ExecutionError::PayableWithInternalCallError => {
                write!(f, "Payable with internal call")
            }
            ExecutionError::PayableCallerNotRegisteredError(account_key) => {
                write!(f, "Payable caller is not a registered account: {:?}", account_key)
            }
            ExecutionError::PayableCallerInsufficientFundsError {
                available_sats,
                required_sats,
            } => {
                write!(
                    f,
                    "Payable caller holds {} sats but the call authorised {} sats",
                    available_sats, required_sats
                )
            }
            ExecutionError::PayableContractNotRegisteredError(contract_id) => {
                write!(
                    f,
                    "Payable destination contract is not registered: {:?}",
                    contract_id
                )
            }
            ExecutionError::PayableCallerBalanceDownError(error) => {
                write!(f, "Payable caller debit failed: {:?}", error)
            }
            ExecutionError::PayableContractBalanceUpError(error) => {
                write!(f, "Payable contract credit failed: {:?}", error)
            }
            ExecutionError::InvalidStackEndingError => {
                write!(f, "Invalid stack ending")
            }
            ExecutionError::BaseOpsPriceMismatchError => {
                write!(f, "Base ops price mismatch")
            }
            ExecutionError::OpcodeIndexOutOfBoundsError => {
                write!(f, "Opcode index out of bounds")
            }
        }
    }
}
