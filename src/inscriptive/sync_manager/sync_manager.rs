use crate::{
    constructive::txout_types::payload::payload::{genesis_payload, Payload},
    inscriptive::sync_manager::errors::construction_error::SMConstructionError,
    operative::run_args::chain::Chain,
};
use bitcoin::hashes::Hash;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A struct for managing the sync tips of the Bitcoin and cube batch.
pub struct SyncManager {
    // Synced flag.
    synced: bool,

    // Bitcoin sync height tip.
    bitcoin_sync_height_tip: u64,

    // Bitcoin block hash at the sync height tip. Used to notice a reorg below the finalized tip.
    bitcoin_sync_block_hash: Option<[u8; 32]>,

    // Cube batch sync height tip.
    cube_batch_sync_height_tip: u64,

    // Payload tip.
    payload_tip: Payload,

    // In-storage db.
    db: sled::Db,
}

/// Guarded sync manager.
#[allow(non_camel_case_types)]
pub type SYNC_MANAGER = Arc<Mutex<SyncManager>>;

impl SyncManager {
    pub fn new(chain: Chain) -> Result<SYNC_MANAGER, SMConstructionError> {
        // 1 Open the sync manager db.
        let db_path = format!("storage/{}/sync_manager", chain);
        let db = sled::open(db_path).map_err(SMConstructionError::DBOpenError)?;

        // 2 Get the bitcoin sync height tip from the db.
        let bitcoin_sync_height_tip: u64 = db
            .get(b"bitcoin_sync_height_tip")
            .ok()
            .flatten()
            .and_then(|val| val.as_ref().try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0);

        // 2.b Get the bitcoin block hash at the sync height tip from the db.
        let bitcoin_sync_block_hash: Option<[u8; 32]> = db
            .get(b"bitcoin_sync_block_hash")
            .ok()
            .flatten()
            .and_then(|val| val.as_ref().try_into().ok().map(|bytes: [u8; 32]| bytes));

        // 3 Get the cube batch sync height tip from the db.
        let cube_batch_sync_height_tip: u64 = db
            .get(b"cube_batch_sync_height_tip")
            .ok()
            .flatten()
            .and_then(|val| val.as_ref().try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0);

        // 4 Get the payload tip from the db.
        let payload_tip: Payload = {
            db.get(b"payload_tip")
                .ok()
                .flatten()
                .or_else(|| db.get(b"prev_payload").ok().flatten())
                .and_then(|payload_bytes| Payload::deserialize(payload_bytes.as_ref()))
                .unwrap_or_else(|| genesis_payload(chain))
        };

        // 5 Construct the sync manager.
        let sync_manager = SyncManager {
            synced: false,
            bitcoin_sync_height_tip,
            bitcoin_sync_block_hash,
            cube_batch_sync_height_tip,
            payload_tip,
            db,
        };

        // 6 Guard the sync manager.
        let sync_manager = Arc::new(Mutex::new(sync_manager));

        // 7 Return the sync manager.
        Ok(sync_manager)
    }

    /// Sets the synced flag.
    pub fn set_synced(&mut self, synced: bool) {
        self.synced = synced;
    }

    /// Returns the synced flag.
    pub fn is_synced(&self) -> bool {
        self.synced
    }

    /// Returns the bitcoin sync height tip.
    pub fn bitcoin_sync_height_tip(&self) -> u64 {
        self.bitcoin_sync_height_tip
    }

    /// Returns the cube batch sync height tip.
    pub fn cube_batch_sync_height_tip(&self) -> u64 {
        self.cube_batch_sync_height_tip
    }

    /// Returns the cube batch transaction id tip.
    pub fn cube_batch_tx_id_tip(&self) -> [u8; 32] {
        self.payload_tip
            .location()
            .map(|(outpoint, _)| outpoint.txid)
            .expect("Payload tip location must exist to get cube batch tx id tip")
            .to_raw_hash()
            .to_byte_array()
    }

    /// Returns the payload tip.
    pub fn payload_tip(&self) -> Payload {
        self.payload_tip.clone()
    }

    /// Returns the Bitcoin block hash at the sync height tip, when one was recorded.
    pub fn bitcoin_sync_block_hash(&self) -> Option<[u8; 32]> {
        self.bitcoin_sync_block_hash
    }

    /// Sets the bitcoin sync tip: height plus the hash of the block at that height.
    pub fn set_bitcoin_sync_tip(&mut self, height: u64, block_hash: [u8; 32]) {
        // Update in-memory.
        self.bitcoin_sync_height_tip = height;
        self.bitcoin_sync_block_hash = Some(block_hash);

        // Update in-db. Both keys move together so a restart compares the same observation.
        let mut batch = sled::Batch::default();
        batch.insert(
            b"bitcoin_sync_height_tip".to_vec(),
            height.to_be_bytes().to_vec(),
        );
        batch.insert(b"bitcoin_sync_block_hash".to_vec(), block_hash.to_vec());
        let _ = self.db.apply_batch(batch);
    }

    /// Resets the Cube batch tip to genesis while keeping the Bitcoin scan progress.
    ///
    /// Used by commit reconciliation: the chain-derived UTXO set stays valid, while every
    /// batch-derived manager is rebuilt by replaying the archived batches from height one.
    pub fn reset_cube_sync_to_genesis(&mut self, chain: Chain) {
        // Reset in-memory.
        self.cube_batch_sync_height_tip = 0;
        self.payload_tip = genesis_payload(chain);
        self.synced = false;

        // Reset in-db.
        let mut batch = sled::Batch::default();
        batch.insert(b"cube_batch_sync_height_tip".to_vec(), 0u64.to_be_bytes().to_vec());
        if let Some(payload_bytes) = self.payload_tip.serialize() {
            batch.insert(b"payload_tip".to_vec(), payload_bytes);
        }
        let _ = self.db.apply_batch(batch);
    }

    /// Sets the cube batch sync height tip.
    pub fn set_cube_batch_sync_height_tip(&mut self, height: u64) {
        // Update in-memory.
        self.cube_batch_sync_height_tip = height;

        // Update in-db.
        let _ = self
            .db
            .insert(b"cube_batch_sync_height_tip", height.to_be_bytes().to_vec());
    }

    /// Sets the payload tip.
    pub fn set_payload_tip(&mut self, payload_tip: Payload) {
        // Update in-memory.
        self.payload_tip = payload_tip.clone();

        // Update in-db.
        if let Some(payload_bytes) = payload_tip.serialize() {
            let _ = self.db.insert(b"payload_tip", payload_bytes);
        }
    }
}

/// Returns whether an observed block hash proves a reorg below the recorded finalized tip.
///
/// A missing observation on either side is not evidence: the node may be behind or the tip may
/// simply not have been recorded yet.
pub fn is_tip_reorg(stored: Option<[u8; 32]>, observed: Option<[u8; 32]>) -> bool {
    matches!((stored, observed), (Some(stored), Some(observed)) if stored != observed)
}

/// Erases the sync manager by db path.
pub fn erase_sync_manager(chain: Chain) {
    // Sync manager db path.
    let sync_manager_db_path = format!("storage/{}/sync_manager", chain);

    // Erase the sync manager db path.
    let _ = std::fs::remove_dir_all(sync_manager_db_path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_changed_tip_hash_is_a_reorg() {
        // A different hash at the recorded height is the only positive signal.
        assert!(is_tip_reorg(Some([1u8; 32]), Some([2u8; 32])));

        // Same hash: the finalized block is still canonical.
        assert!(!is_tip_reorg(Some([1u8; 32]), Some([1u8; 32])));

        // No stored hash: nothing was finalized yet.
        assert!(!is_tip_reorg(None, Some([1u8; 32])));

        // No observation: the node is behind or unreachable, not a reorg.
        assert!(!is_tip_reorg(Some([1u8; 32]), None));
        assert!(!is_tip_reorg(None, None));
    }

    #[tokio::test]
    async fn the_tip_height_and_hash_survive_a_reopen() {
        let chain = Chain::Testbed;
        erase_sync_manager(chain);

        // 1 Record a tip and drop the handle (the process exits).
        {
            let sync_manager = SyncManager::new(chain).expect("sync manager");
            sync_manager
                .lock()
                .await
                .set_bitcoin_sync_tip(7, [9u8; 32]);
        }

        // 2 Reopen and observe the same height and hash.
        {
            let sync_manager = SyncManager::new(chain).expect("sync manager");
            let manager = sync_manager.lock().await;
            assert_eq!(manager.bitcoin_sync_height_tip(), 7);
            assert_eq!(manager.bitcoin_sync_block_hash(), Some([9u8; 32]));
        }

        // 3 Reset the Cube tip without losing the Bitcoin tip.
        {
            let sync_manager = SyncManager::new(chain).expect("sync manager");
            let mut manager = sync_manager.lock().await;
            manager.reset_cube_sync_to_genesis(chain);
            assert_eq!(manager.cube_batch_sync_height_tip(), 0);
            assert_eq!(manager.bitcoin_sync_height_tip(), 7);
            assert_eq!(manager.bitcoin_sync_block_hash(), Some([9u8; 32]));
        }

        erase_sync_manager(chain);
    }
}
