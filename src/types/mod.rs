use alloy::consensus::TypedTransaction;
use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use sha3::Digest;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Arc<Vec<TypedTransaction>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash: B256,
    pub block_number: u64,
    pub difficulty: u64,
    pub timestamp: u64,
    pub nonce: u64,
    pub coinbase: B256, //address
    pub receipt_hash: B256,
    pub bloom: String,
    pub state_root: B256,
    pub tx_root: B256,
}

impl Default for BlockHeader {
    fn default() -> Self {
        BlockHeader {
            parent_hash: B256::ZERO,
            block_number: 0,
            difficulty: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            nonce: 0,
            coinbase: B256::ZERO,
            receipt_hash: B256::ZERO,
            bloom: String::new(),
            state_root: B256::ZERO,
            tx_root: B256::ZERO,
        }
    }
}
