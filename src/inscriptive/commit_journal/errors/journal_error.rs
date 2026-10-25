/// Errors associated with the `CommitJournal`.
#[derive(Debug, Clone)]
pub enum CommitJournalError {
    /// The journal database could not be opened.
    DBOpenError(sled::Error),
    /// A journal key could not be read or written.
    DBError(sled::Error),
    /// The batch record could not be serialized for the journal.
    SerializeFailed,
    /// The pending value is shorter than the height prefix.
    CorruptPendingValue(usize),
    /// The pending height prefix could not be decoded.
    CorruptPendingHeight,
    /// The pending batch record could not be deserialized.
    CorruptPendingRecord(u64),
    /// Another batch height is already in flight and must be reconciled first.
    PendingCommitExists(u64),
}
