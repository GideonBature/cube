use crate::constructive::entries::entry_kinds::call::ext::signature::sighash::error::sighash_error::CallSighashError;

/// Errors associated with verifying a `Call`'s BLS signature.
#[derive(Debug, Clone)]
pub enum CallBLSVerifyError {
    /// The sighash could not be derived.
    SighashError(CallSighashError),
    /// The BLS signature does not verify against the caller's BLS key.
    InvalidBLSSignatureError,
}
