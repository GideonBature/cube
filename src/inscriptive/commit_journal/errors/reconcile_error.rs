/// Errors associated with restart reconciliation.
#[derive(Debug)]
pub enum ReconcileError {
    /// The journal could not be read.
    Journal(crate::inscriptive::commit_journal::errors::journal_error::CommitJournalError),
    /// The archival manager could not be opened.
    Archival(
        crate::inscriptive::archival_manager::errors::construction_error::ArchivalConstructionError,
    ),
    /// A manager could not be reconstructed.
    ManagerConstruction(String),
    /// The archived history does not contain a batch the replay needs.
    MissingArchivedRecord(u64),
    /// Replaying an archived batch failed.
    ReplayFailed(
        u64,
        crate::executive::exec_ctx::errors::batch_execution_error::BatchExecutionError,
    ),
    /// The replayed batch does not match the archived one.
    ReplayMismatch(u64),
    /// The in-flight record could not be archived before the journal was closed.
    ArchivalInsert(String),
    /// The journal names a height that cannot be the first batch (heights start at one).
    InvalidPendingHeight(u64),
}
