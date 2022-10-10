use std::collections::HashMap;

use ckb_sdk::traits::{DefaultTransactionDependencyProvider, TransactionDependencyProvider};
use ckb_types::{
    bytes::Bytes,
    core::{HeaderView, TransactionView},
    packed::{Byte32, CellOutput, OutPoint},
};

pub struct TxDep {
    inner: DefaultTransactionDependencyProvider,
    // tx_cache: HashMap<Byte32, TransactionView>,
    cell_cache: HashMap<OutPoint, (CellOutput, Bytes)>,
    // header_cache: HashMap<Byte32, HeaderView>,
}

impl TxDep {
    pub fn new(url: &str, cache_capacity: usize) -> TxDep {
        return TxDep {
            inner: DefaultTransactionDependencyProvider::new(url, cache_capacity),
            // tx_cache: HashMap::default(),
            cell_cache: HashMap::default(),
            // header_cache: HashMap::default(),
        };
    }

    pub fn add_cell(&mut self, out_point: OutPoint, cell_output: CellOutput, data: Bytes) {
        self.cell_cache.insert(out_point, (cell_output, data));
    }
}

impl TransactionDependencyProvider for TxDep {
    fn get_transaction(
        &self,
        tx_hash: &Byte32,
    ) -> Result<TransactionView, ckb_sdk::traits::TransactionDependencyError> {
        return self.inner.get_transaction(tx_hash);
    }

    fn get_cell(
        &self,
        out_point: &OutPoint,
    ) -> Result<CellOutput, ckb_sdk::traits::TransactionDependencyError> {
        if let Some((cell_output, _)) = self.cell_cache.get(out_point) {
            println!("get_cell cached");
            return Ok(cell_output.clone());
        }
        return self.inner.get_cell(out_point);
    }

    fn get_cell_data(
        &self,
        out_point: &OutPoint,
    ) -> Result<ckb_types::bytes::Bytes, ckb_sdk::traits::TransactionDependencyError> {
        if let Some((_, data)) = self.cell_cache.get(out_point) {
            return Ok(data.clone());
        }
        return self.inner.get_cell_data(out_point);
    }

    fn get_header(
        &self,
        block_hash: &Byte32,
    ) -> Result<HeaderView, ckb_sdk::traits::TransactionDependencyError> {
        return self.inner.get_header(block_hash);
    }
}
