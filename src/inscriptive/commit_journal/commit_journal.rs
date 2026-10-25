//! A durable write-ahead journal for the multi-store batch commit.
//!
//! A batch commit touches six Sled databases that cannot share a transaction. The journal records
//! the exact `BatchRecord` that is about to be applied, and it is written *before* the first
//! manager mutates anything. Two outcomes then exist:
//!
//! - the commit finishes and the journal entry is removed, or
//! - the process stops somewhere inside the commit and the journal entry survives.
//!
//! In the second case the entry is the record of what was being applied. Startup reconciliation
//! (see `reconcile`) replays the archived batches up to and including that height, which rebuilds
//! every manager from a known point instead of guessing which of them committed.
//!
//! The journal is not a general transaction manager: it stores at most one in-flight batch.

use crate::constructive::bitcoiny::batch_record::batch_record::BatchRecord;
use crate::inscriptive::commit_journal::errors::journal_error::CommitJournalError;
use crate::operative::run_args::chain::Chain;
use std::sync::Arc;

/// The key holding the in-flight batch: 8 height bytes followed by the serialized record.
const PENDING_KEY: &[u8] = b"pending";

/// The key holding the height of the last batch whose commit finished.
const LAST_COMMITTED_KEY: &[u8] = b"last_committed";

/// The key holding the name of the last manager that was applied, for diagnostics only.
const PROGRESS_KEY: &[u8] = b"progress";

/// A batch that was being committed when the process stopped.
#[derive(Clone)]
pub struct PendingCommit {
    /// The batch height whose commit was interrupted.
    pub height: u64,
    /// The full recorded batch, including its container and payload.
    pub record: BatchRecord,
}

/// A durable write-ahead journal for batch commits.
#[derive(Clone)]
pub struct CommitJournal {
    // The journal database.
    db: Arc<sled::Db>,
}

impl CommitJournal {
    /// Opens the journal for a chain.
    pub fn open(chain: Chain) -> Result<Self, CommitJournalError> {
        // 1 Open the journal db.
        let db_path = format!("storage/{}/commit_journal", chain);
        let db = sled::open(db_path).map_err(CommitJournalError::DBOpenError)?;

        // 2 Return the journal.
        Ok(Self { db: Arc::new(db) })
    }

    /// Writes the intent to commit a batch and makes it durable before any manager is touched.
    ///
    /// A different height already in flight is a programming error: `execute_batch` refuses to run
    /// while a pending commit exists, so the only way to reach this is a caller that reused a
    /// journal across an unreconciled restart.
    pub fn begin(&self, record: &BatchRecord) -> Result<(), CommitJournalError> {
        // 1 Refuse to overwrite another batch's intent.
        if let Some(pending) = self.pending()? {
            if pending.height != record.batch_height {
                return Err(CommitJournalError::PendingCommitExists(pending.height));
            }
        }

        // 2 Encode the height prefix and the batch record.
        let record_bytes = record
            .serialize()
            .ok_or(CommitJournalError::SerializeFailed)?;
        let mut value = Vec::with_capacity(8 + record_bytes.len());
        value.extend_from_slice(&record.batch_height.to_be_bytes());
        value.extend_from_slice(&record_bytes);

        // 3 Write the intent and reset the progress marker.
        let mut batch = sled::Batch::default();
        batch.insert(PENDING_KEY, value);
        batch.insert(PROGRESS_KEY, b"prepared".to_vec());
        self.db
            .apply_batch(batch)
            .map_err(CommitJournalError::DBError)?;

        // 4 Flush so the intent exists before the managers change.
        self.db.flush().map_err(CommitJournalError::DBError)?;

        // 5 Return success.
        Ok(())
    }

    /// Records which manager finished applying, for the diagnostic printed after a crash.
    pub fn note_manager(&self, manager: &str) {
        let _ = self.db.insert(PROGRESS_KEY, manager.as_bytes().to_vec());
    }

    /// Marks the in-flight commit as finished and removes the intent.
    pub fn finish(&self, height: u64) -> Result<(), CommitJournalError> {
        // 1 Write the committed height and clear the intent in one atomic batch.
        let mut batch = sled::Batch::default();
        batch.insert(LAST_COMMITTED_KEY, height.to_be_bytes().to_vec());
        batch.remove(PENDING_KEY);
        batch.remove(PROGRESS_KEY);
        self.db
            .apply_batch(batch)
            .map_err(CommitJournalError::DBError)?;

        // 2 Flush before returning, so the next process cannot see the intent again.
        self.db.flush().map_err(CommitJournalError::DBError)?;

        // 3 Return success.
        Ok(())
    }

    /// Returns the in-flight commit, when one exists.
    pub fn pending(&self) -> Result<Option<PendingCommit>, CommitJournalError> {
        // 1 Read the pending value.
        let Some(value) = self
            .db
            .get(PENDING_KEY)
            .map_err(CommitJournalError::DBError)?
        else {
            return Ok(None);
        };

        // 2 Require the height prefix.
        if value.len() < 8 {
            return Err(CommitJournalError::CorruptPendingValue(value.len()));
        }
        let height = u64::from_be_bytes(
            value[..8]
                .try_into()
                .map_err(|_| CommitJournalError::CorruptPendingHeight)?,
        );

        // 3 Deserialize the record and check its height.
        let record = BatchRecord::deserialize(&value[8..])
            .ok_or(CommitJournalError::CorruptPendingRecord(height))?;
        if record.batch_height != height {
            return Err(CommitJournalError::CorruptPendingRecord(height));
        }

        // 4 Return the pending commit.
        Ok(Some(PendingCommit { height, record }))
    }

    /// Returns the name of the last manager that finished applying, when a commit is in flight.
    pub fn progress(&self) -> Option<String> {
        self.db
            .get(PROGRESS_KEY)
            .ok()
            .flatten()
            .and_then(|value| String::from_utf8(value.to_vec()).ok())
    }

    /// Returns the height of the last batch whose commit finished.
    pub fn last_committed(&self) -> Option<u64> {
        self.db
            .get(LAST_COMMITTED_KEY)
            .ok()
            .flatten()
            .and_then(|value| value.as_ref().try_into().ok().map(u64::from_be_bytes))
    }
}

/// Erases the journal by db path.
pub fn erase_commit_journal(chain: Chain) {
    // Journal db path.
    let journal_db_path = format!("storage/{}/commit_journal", chain);

    // Erase the journal db path.
    let _ = std::fs::remove_dir_all(journal_db_path);
}
