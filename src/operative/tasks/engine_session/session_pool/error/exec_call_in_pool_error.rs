/// Errors associated with executing a `Call` entry in the `SessionPool`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExecCallInPoolError {
    /// The session is inactive.
    SessionInactiveError,
    /// The session is suspended.
    SessionSuspendedError,
    /// The session has taken a break.
    SessionBreakError,
    /// The pool holds the maximum number of entries.
    PoolOverloadedError,
    /// The pool has no batch information.
    BatchInfoNotFoundError,
    /// The `Call`'s BLS signature did not verify against the caller's BLS key.
    CallBLSVerifyError(String),
    /// The `Call` failed its end-to-end pre-validation.
    CallValidateOverallError(String),
    /// The `Call` failed during execution.
    CallExecutionError(String),
    /// The entry ID could not be derived for the executed entry.
    EntryIdDerivationError,
}
