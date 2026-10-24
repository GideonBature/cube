use crate::constructive::entries::entry_kinds::call::ext::signature::sighash::error::sighash_error::CallSighashError;

/// Errors associated with signing a `Call` with BLS.
#[derive(Debug, Clone)]
pub enum CallBLSSignError {
    SighashError(CallSighashError),
}
