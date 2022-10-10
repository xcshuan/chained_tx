use std::collections::HashSet;

use ckb_sdk::traits::{CellCollector, DefaultCellCollector, LiveCell, OffchainCellCollector};
use ckb_types::H256;

pub struct CellCollectorWrapper {
    pub inner: DefaultCellCollector,
    pub offchain: OffchainCellCollector,
}

impl CellCollectorWrapper {
    #[allow(dead_code)]
    pub fn new(
        indexer_client: &str,
        ckb_client: &str,
        locked_cells: HashSet<(H256, u32)>,
        live_cells: Vec<LiveCell>,
        max_mature_number: u64,
    ) -> CellCollectorWrapper {
        CellCollectorWrapper {
            inner: DefaultCellCollector::new(indexer_client, ckb_client),
            offchain: OffchainCellCollector::new(locked_cells, live_cells, max_mature_number),
        }
    }
}

impl CellCollector for CellCollectorWrapper {
    fn collect_live_cells(
        &mut self,
        query: &ckb_sdk::traits::CellQueryOptions,
        apply_changes: bool,
    ) -> Result<(Vec<LiveCell>, u64), ckb_sdk::traits::CellCollectorError> {
        if let Ok(res) = self.offchain.collect_live_cells(query, apply_changes) {
            return Ok(res)
        }
        return self.inner.collect_live_cells(query, apply_changes)
    }

    fn lock_cell(
        &mut self,
        out_point: ckb_types::packed::OutPoint,
    ) -> Result<(), ckb_sdk::traits::CellCollectorError> {
        if let Ok(res) = self.offchain.lock_cell(out_point.clone()) {
            return Ok(res)
        }
        return self.inner.lock_cell(out_point)
    }

    fn apply_tx(
        &mut self,
        tx: ckb_types::packed::Transaction,
    ) -> Result<(), ckb_sdk::traits::CellCollectorError> {
        if let Ok(res) = self.offchain.apply_tx(tx.clone()) {
            return Ok(res)
        }
        return self.inner.apply_tx(tx)
    }

    fn reset(&mut self) {
        self.inner.reset();
        self.offchain.reset();
    }
}
