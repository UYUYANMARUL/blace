pub mod db;
pub mod mpt;
pub mod rpc;
pub mod types;

use alloy::consensus::TypedTransaction;
use alloy::primitives::keccak256;
use alloy::primitives::B256;
use alloy::primitives::U256;
use alloy::primitives::U64;
use bytes::Bytes;
use db::block_db;
use db::block_db::BlockDataDB;
use mpt::{EthTrie, MemoryDB, Trie, TrieError};
use rpc::AppChainRPC;
use rusty_leveldb::{AsyncDB, Options};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::interval;
use tracing::info;

#[derive(Debug, Serialize, Deserialize)]
pub struct Account {
    code: Bytes,
    storage: Bytes,
    balance: U256,
    nonce: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Arc<Vec<TypedTransaction>>,
    pub hash: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub parent_hash: B256,
    pub block_number: u64,
    pub difficulty: u64,
    pub timestamp: u64,
    pub nonce: u64,
    pub coinbase: B256, //
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
            state_root: B256::from_str(
                "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            )
            .unwrap(),
            tx_root: B256::from_str(
                "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
            )
            .unwrap(),
        }
    }
}

impl Block {
    pub fn genesis_block() -> Self {
        let transactions = Arc::new(Vec::new());
        let mut header = BlockHeader::default();
        header.timestamp = 0;

        let block_hash = B256::from_slice(&Keccak256::digest(
            &serde_json::to_vec(&header).unwrap_or_default(),
        ));

        Block {
            header,
            transactions,
            hash: block_hash,
        }
    }

    pub async fn calculate_transaction_root(transactions: &[TypedTransaction]) -> B256 {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut mpt = EthTrie::new(memdb);

        for transaction in transactions {
            // mpt.insert(key, value).await
        }

        mpt.root_hash().await.unwrap()
    }

    pub async fn new(
        parent_hash: B256,
        block_number: u64,
        transactions: Vec<TypedTransaction>,
    ) -> Self {
        let transactions = Arc::new(transactions);
        let tx_root = Self::calculate_transaction_root(&transactions).await;

        let header = BlockHeader {
            parent_hash,
            block_number,
            tx_root,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ..Default::default()
        };

        let block_hash = B256::from_slice(&Keccak256::digest(
            &serde_json::to_vec(&header).unwrap_or_default(),
        ));

        Block {
            header,
            transactions,
            hash: block_hash,
        }
    }

    pub async fn from_previous_block(
        &self,
        transactions: Vec<TypedTransaction>,
        state_root: B256,
    ) -> Self {
        let transactions = Arc::new(transactions);
        let tx_root = Self::calculate_transaction_root(&transactions).await;

        let parent_hash = B256::from_slice(&Keccak256::digest(
            &serde_json::to_vec(&self.header).unwrap_or_default(),
        ));

        let header = BlockHeader {
            parent_hash,
            block_number: self.header.block_number + 1,
            tx_root,
            state_root,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            ..Default::default()
        };

        let block_hash = B256::from_slice(&Keccak256::digest(
            &serde_json::to_vec(&header).unwrap_or_default(),
        ));

        Block {
            header,
            transactions,
            hash: block_hash,
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        let config = bincode::config::standard()
            .with_fixed_int_encoding()
            .with_big_endian();

        Bytes::from(bincode::serde::encode_to_vec(&self, config).unwrap())
    }
}

pub struct AppChain {
    mempool: HashMap<B256, TypedTransaction>,
    meta_db: Arc<RwLock<AsyncDB>>,
    state_db: Arc<AsyncDB>,
    block_db: Arc<RwLock<BlockDataDB>>,
    appchain_rpc: AppChainRPC,
    last_finalized_block: Option<B256>,
    last_produced_block: B256,
}

impl AppChain {
    pub async fn new() -> Self {
        let meta_db = Arc::new(RwLock::new(
            AsyncDB::new("meta", Options::default()).unwrap(),
        ));

        let state_db = Arc::new(AsyncDB::new("state", Options::default()).unwrap());
        let block_db = Arc::new(RwLock::new(BlockDataDB::new()));

        EthTrie::new(state_db.clone()).root_hash().await;

        let meta_db_read = meta_db.read().await;

        let last_produced_block = if let Some(bytes) = meta_db_read
            .get(b"last_produced_block".to_vec())
            .await
            .ok()
            .flatten()
        {
            B256::from_slice(&bytes)
        } else {
            let genesis_block = Block::genesis_block();
            let hash = genesis_block.hash;

            block_db
                .write()
                .await
                .insert_block(hash.to_vec(), genesis_block)
                .await;
            hash
        };

        drop(meta_db_read);

        println!("last Produced block is {:?}", last_produced_block);

        let last_finalized_block = meta_db
            .read()
            .await
            .get(b"last_finalized_block".to_vec())
            .await
            .ok()
            .flatten()
            .map(|bytes| B256::from_slice(&bytes));

        AppChain {
            mempool: HashMap::new(),
            meta_db,
            state_db,
            block_db,
            appchain_rpc: AppChainRPC::new(),
            last_finalized_block,
            last_produced_block,
        }
    }

    async fn save_produced_block(&mut self, block: Block) {
        let meta_db = self.meta_db.write().await;
        let mut block_db = self.block_db.write().await;
        let block_hash = block.hash;

        meta_db
            .put(b"last_produced_block".to_vec(), block.hash.to_vec())
            .await;

        block_db.insert_block(block_hash.to_vec(), block).await;
        meta_db.flush().await;
        self.last_produced_block = block_hash;
    }

    async fn save_finalized_block(&mut self, hash: &B256) {
        self.meta_db
            .write()
            .await
            .put(b"last_finalized_block".to_vec(), hash.to_vec())
            .await;

        self.last_finalized_block = Some(*hash);
    }

    pub async fn process_tx_in_mempool(&mut self) {
        // create vec of transactions
        let (transaction_keys, transactions): (Vec<B256>, Vec<TypedTransaction>) =
            self.mempool.iter().map(|(k, v)| (*k, v.clone())).unzip();

        for (i, tx) in transactions.iter().enumerate() {
            println!("Transaction {}: {:?}", i + 1, tx);
        }

        // get last produced block
        let last_block = self
            .block_db
            .read()
            .await
            .get_block(self.last_produced_block.to_vec())
            .await
            .unwrap_or(Block::genesis_block());

        // create trie from last produced block root
        let mut state = EthTrie::from(self.state_db.clone(), last_block.header.state_root)
            .await
            .unwrap();

        println!("Last block hash: {:?}", self.last_produced_block);
        println!("Last block data: {:#?}", last_block);
        println!("{:?}", last_block.header.state_root);

        // apply transactions to state
        for tx in transactions {}

        // saves all transactions and state transition to create new root and save block after that
        let root_hash = state.root_hash().await.unwrap();

        let block: Block = last_block.from_previous_block(vec![], root_hash).await;

        let block_hash = block.hash;

        println!("block: {:#?}", block);
        self.save_produced_block(block).await;
    }

    pub async fn start(self) {
        let appchain = Arc::new(RwLock::new(self));
        let mut handles: Vec<JoinHandle<()>> = vec![];

        {
            let appchain = appchain.clone();
            handles.push(tokio::spawn(async move {
                let mut interval = interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    appchain.write().await.process_tx_in_mempool().await;
                    println!("Block created");
                }
            }));
        }
        handles.push(tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                println!("Task 2 executed every minute");
            }
        }));

        for handle in handles {
            let _ = handle.await;
        }
    }
}
