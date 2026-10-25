//! Restart reconciliation for an interrupted batch commit.
//!
//! When the process stops inside `ExecCtx::apply_changes`, the six manager stores may be at
//! different batch heights. The journal names the batch that was in flight, and the archival store
//! holds every earlier batch. Reconciliation therefore rebuilds the batch-derived managers from a
//! known point instead of trying to infer which store committed:
//!
//! 1. read the in-flight record from the journal;
//! 2. collect archived records `1..=height`;
//! 3. reset the Cube tips (the Bitcoin scan tip and the UTXO set are chain-derived and survive);
//! 4. erase the batch-derived managers;
//! 5. re-execute the records in order in replay mode;
//! 6. archive the in-flight record if the crash happened before it was written;
//! 7. close the journal intent.
//!
//! Replay is deterministic: the record carries the exact batch container, timestamp and payload.
//! The replayed record is compared against the archived one, so a mismatch stops the restart rather
//! than serving a diverged state. Recovery is O(history) and requires archival storage; a pruned
//! node refuses to start instead of guessing.

use crate::constructive::entry::entry::entry::Entry;
use crate::executive::exec_ctx::exec_ctx::ExecCtx;
use crate::inscriptive::archival_manager::archival_manager::ArchivalManager;
use crate::inscriptive::coin_manager::coin_manager::{
    erase_coin_manager, CoinManager, COIN_MANAGER,
};
use crate::inscriptive::commit_journal::commit_journal::CommitJournal;
use crate::inscriptive::commit_journal::errors::reconcile_error::ReconcileError;
use crate::inscriptive::flame_manager::flame_manager::{
    erase_flame_manager, FlameManager, FLAME_MANAGER,
};
use crate::inscriptive::graveyard::graveyard::{erase_graveyard, Graveyard, GRAVEYARD};
use crate::inscriptive::params_manager::params_manager::{ParamsManager, PARAMS_MANAGER};
use crate::inscriptive::privileges_manager::privileges_manager::{
    erase_privileges_manager, PrivilegesManager, PRIVILEGES_MANAGER,
};
use crate::inscriptive::registry::registry::{erase_registry, Registry, REGISTRY};
use crate::inscriptive::state_manager::state_manager::{
    erase_state_manager, StateManager, STATE_MANAGER,
};
use crate::inscriptive::sync_manager::sync_manager::{SyncManager, SYNC_MANAGER};
use crate::inscriptive::utxo_set::utxo_set::{UTXOSet, UTXO_SET};
use crate::operative::run_args::chain::Chain;
use std::sync::Arc;

/// What a startup reconciliation found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reconciliation {
    /// There was no interrupted commit.
    NothingPending,
    /// An interrupted commit was replayed and the journal was closed.
    RolledForward {
        /// The batch height that was in flight.
        height: u64,
        /// How many archived records were replayed, including the in-flight one.
        replayed_batches: u64,
        /// Whether the in-flight record had to be added to the archival store.
        archived_record_inserted: bool,
    },
}

/// Reconciles a commit that did not finish, before the runtime constructs its managers.
///
/// Must be called while no manager handle for this chain is open: it erases and reopens the
/// batch-derived stores.
pub async fn reconcile_pending_commit(
    chain: Chain,
    engine_key: [u8; 32],
) -> Result<Reconciliation, ReconcileError> {
    // 1 Read the journal. Without a pending commit there is nothing to reconcile.
    let journal = CommitJournal::open(chain).map_err(ReconcileError::Journal)?;
    let Some(pending) = journal.pending().map_err(ReconcileError::Journal)? else {
        return Ok(Reconciliation::NothingPending);
    };
    if pending.height == 0 {
        return Err(ReconcileError::InvalidPendingHeight(pending.height));
    }

    // 2 Collect the record for every height up to the in-flight one. The in-flight record comes
    //   from the journal, because the crash may have happened before it was archived.
    let archival_manager = ArchivalManager::new(chain).map_err(ReconcileError::Archival)?;
    let mut records = Vec::with_capacity(pending.height as usize);
    for height in 1..=pending.height {
        let record = if height == pending.height {
            pending.record.clone()
        } else {
            archival_manager
                .lock()
                .await
                .batch_record_by_height(height)
                .ok_or(ReconcileError::MissingArchivedRecord(height))?
        };
        records.push(record);
    }

    // 3 Reset the Cube tips to genesis but keep the Bitcoin scan progress: the UTXO set is
    //   chain-derived and replay re-applies the same lift removals.
    let sync_manager: SYNC_MANAGER = SyncManager::new(chain)
        .map_err(|_| ReconcileError::ManagerConstruction("sync manager".to_string()))?;
    sync_manager.lock().await.reset_cube_sync_to_genesis(chain);

    // 4 Erase every batch-derived manager. The archival store, the UTXO set and the params
    //   manager are not batch-derived and stay.
    erase_coin_manager(chain);
    erase_flame_manager(chain);
    erase_graveyard(chain);
    erase_registry(chain);
    erase_state_manager(chain);
    erase_privileges_manager(chain);

    // 5 Reconstruct them from empty stores.
    let utxo_set: UTXO_SET = UTXOSet::new(chain)
        .ok_or_else(|| ReconcileError::ManagerConstruction("utxo set".to_string()))?;
    let registry: REGISTRY = Registry::new(chain)
        .map_err(|_| ReconcileError::ManagerConstruction("registry".to_string()))?;
    let graveyard: GRAVEYARD = Graveyard::new(chain)
        .map_err(|_| ReconcileError::ManagerConstruction("graveyard".to_string()))?;
    let coin_manager: COIN_MANAGER = CoinManager::new(chain)
        .map_err(|_| ReconcileError::ManagerConstruction("coin manager".to_string()))?;
    let flame_manager: FLAME_MANAGER = FlameManager::new(chain)
        .map_err(|_| ReconcileError::ManagerConstruction("flame manager".to_string()))?;
    let state_manager: STATE_MANAGER = StateManager::new(chain)
        .map_err(|_| ReconcileError::ManagerConstruction("state manager".to_string()))?;
    let privileges_manager: PRIVILEGES_MANAGER = PrivilegesManager::new(chain)
        .map_err(|_| ReconcileError::ManagerConstruction("privileges manager".to_string()))?;
    let params_manager: PARAMS_MANAGER = ParamsManager::new(chain)
        .map_err(|_| ReconcileError::ManagerConstruction("params manager".to_string()))?;

    // 5.b A batch apply removes the lift outpoints it consumes from the utxo set. Replay starts
    //     at height one, so restore every lift the replayed records spend; the records carry the
    //     full lift with its txout.
    {
        let mut _utxo_set = utxo_set.lock().await;
        for record in records.iter() {
            for (_, entry) in record.entries.iter() {
                if let Entry::Liftup(liftup) = entry {
                    for lift in liftup.lift_tx_inputs.iter() {
                        _utxo_set.insert_utxo(&lift.outpoint(), &lift.txout());
                    }
                }
            }
        }
    }

    // 6 Replay in replay mode: no journal writes and no duplicate archival inserts.
    let exec_ctx = ExecCtx::construct(
        engine_key,
        Arc::clone(&sync_manager),
        Arc::clone(&utxo_set),
        Arc::clone(&registry),
        Arc::clone(&graveyard),
        Arc::clone(&coin_manager),
        Arc::clone(&flame_manager),
        Arc::clone(&state_manager),
        Arc::clone(&privileges_manager),
        Arc::clone(&params_manager),
        Some(Arc::clone(&archival_manager)),
        Some(journal.clone()),
    );
    exec_ctx.lock().await.set_replaying(true);

    for record in records.iter() {
        // 6.1 Execute the archived batch.
        let produced = {
            let mut _exec_ctx = exec_ctx.lock().await;
            _exec_ctx.execute_batch(&record.batch_container).await
        }
        .map_err(|error| ReconcileError::ReplayFailed(record.batch_height, error))?;

        // 6.2 The replay must reproduce the archived batch, not merely execute.
        let same_payload = match (
            produced.new_payload.serialize(),
            record.new_payload.serialize(),
        ) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        };
        let same_entries = produced.entries.len() == record.entries.len()
            && produced
                .entries
                .iter()
                .zip(record.entries.iter())
                .all(|((left, _), (right, _))| left == right);
        if produced.batch_txid != record.batch_txid || !same_payload || !same_entries {
            return Err(ReconcileError::ReplayMismatch(record.batch_height));
        }
    }

    // 7 Archive the in-flight record when the crash happened before the insert.
    let archived_record_inserted = {
        let mut _archival_manager = archival_manager.lock().await;
        if _archival_manager
            .batch_record_by_height(pending.height)
            .is_none()
        {
            _archival_manager
                .insert_batch_record(pending.record.clone())
                .map_err(|error| ReconcileError::ArchivalInsert(format!("{error:?}")))?;
            true
        } else {
            false
        }
    };

    // 8 Close the intent. A failure here leaves the record pending, so the next start retries the
    //   replay instead of accepting a half-finished reconciliation.
    journal
        .finish(pending.height)
        .map_err(ReconcileError::Journal)?;

    // 9 Return what was done.
    Ok(Reconciliation::RolledForward {
        height: pending.height,
        replayed_batches: records.len() as u64,
        archived_record_inserted,
    })
}
