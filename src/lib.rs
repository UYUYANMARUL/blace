#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unused_imports)]

pub mod db;
pub mod evm;
pub mod mpt;
pub mod precompiles;
pub mod rpc;
pub mod types;

use alloy::consensus::transaction::SignerRecoverable;
use alloy::consensus::{
    Account, Block, BlockBody, Header, Transaction as AlloyTransaction, TxEnvelope,
};

use alloy::eips::Encodable2718;
use alloy::primitives::B256;
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use bytes::Bytes;
use evm::database::EvmDB;
use evm::BlaceEvm;
use mpt::{EthTrie, MemoryDB, Trie};
use revm::context::tx::TxEnvBuilder;
use revm::context::{BlockEnv, CfgEnv, TxEnv};
use revm::database::WrapDatabaseAsync;
use revm::inspector::NoOpInspector;
use revm::primitives::hardfork::SpecId;
use revm::primitives::{StorageKey, StorageValue};
use revm::state::AccountStatus;
use revm::Context;
use revm::ExecuteEvm;
use rpc::AppChainRPC;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::interval;

pub const EMPTY_TRIE_ROOT: &str =
    "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

pub struct MyTxEnv(TxEnv);

impl From<&TxEnvelope> for MyTxEnv {
    fn from(tx: &TxEnvelope) -> MyTxEnv {
        MyTxEnv(
            TxEnvBuilder::new()
                .chain_id(tx.chain_id())
                .kind(tx.kind())
                .value(tx.value())
                .caller(tx.recover_signer().unwrap())
                .tx_type(Some(tx.tx_type().into()))
                .nonce(tx.nonce())
                .data(tx.input().clone())
                .gas_price(tx.gas_price().unwrap_or(0))
                .gas_limit(tx.gas_limit())
                .max_fee_per_gas(tx.max_fee_per_gas())
                .max_fee_per_blob_gas(tx.max_fee_per_blob_gas().unwrap_or(0))
                .blob_hashes(
                    tx.blob_versioned_hashes()
                        .map(|slice| slice.to_vec())
                        .unwrap_or_else(Vec::new),
                )
                .gas_priority_fee(tx.max_priority_fee_per_gas())
                .build_fill(),
        )
    }
}

#[derive(Debug, Serialize, Deserialize, RlpEncodable, RlpDecodable, PartialEq)]
pub struct AppBlock(Block<TxEnvelope>);

#[derive(Serialize)]
struct RpcBlock {
    number: String,
    hash: Option<String>,
    parentHash: String,
    prevrandao: String,
    sha3Uncles: String,
    miner: String,
    stateRoot: String,
    transactionsRoot: String,
    receiptsRoot: String,
    logsBloom: String,
    difficulty: String,
    gasLimit: String,
    gasUsed: String,
    timestamp: String,
    nonce: String,
    extraData: String,
    baseFeePerGas: Option<String>,
    withdrawalsRoot: Option<String>,
    blobGasUsed: Option<String>,
    excessBlobGas: Option<String>,
    parentBeaconBlockRoot: Option<String>,
    transactions: Vec<String>,
    uncles: Vec<Header>,
}

use hex::encode;

impl AppBlock {
    pub fn to_rpc_block(&self) -> RpcBlock {
        let header = &self.0.header;
        let body = &self.0.body;

        RpcBlock {
            number: format!("0x{:x}", header.number),
            hash: Some(header.hash_slow().to_string()),
            prevrandao: "0x0000000000000000000000000000000000000000000000000000000000000001"
                .to_string(),
            parentHash: format!("0x{}", encode(header.parent_hash)),
            sha3Uncles: format!("0x{}", encode(header.ommers_hash)),
            miner: format!("0x{}", encode(header.beneficiary)),
            stateRoot: format!("0x{}", encode(header.state_root)),
            transactionsRoot: format!("0x{}", encode(header.transactions_root)),
            receiptsRoot: format!("0x{}", encode(header.receipts_root)),
            logsBloom: format!("0x{}", encode(header.logs_bloom)),
            difficulty: format!("0x{:x}", header.difficulty),
            gasLimit: format!("0x{:x}", header.gas_limit),
            gasUsed: format!("0x{:x}", header.gas_used),
            timestamp: format!("0x{:x}", header.timestamp),
            nonce: format!("0x{}", encode(header.nonce)),
            extraData: format!("0x{}", encode(&header.extra_data)),
            baseFeePerGas: header.base_fee_per_gas.map(|v| format!("0x")),
            withdrawalsRoot: header.withdrawals_root.map(|v| format!("0x{}", encode(v))),
            blobGasUsed: header.blob_gas_used.map(|v| format!("0x{:x}", v)),
            excessBlobGas: header.excess_blob_gas.map(|v| format!("0x{:x}", v)),
            parentBeaconBlockRoot: header
                .parent_beacon_block_root
                .map(|v| format!("0x{}", encode(v))),
            transactions: vec![],
            uncles: body.ommers.clone(),
        }
    }

    pub fn genesis_block() -> Self {
        let transactions: Vec<TxEnvelope> = Vec::new();
        let mut header = Header::default();
        header.timestamp = 0;

        let block_hash = B256::from_slice(&Keccak256::digest(
            &serde_json::to_vec(&header).unwrap_or_default(),
        ));

        let block = Block::new(header, BlockBody::default());
        AppBlock(block)
    }

    pub async fn calculate_transaction_root(transactions: &[TxEnvelope]) -> B256 {
        let memdb = Arc::new(MemoryDB::new(true));
        let mut mpt = EthTrie::new(memdb);

        for transaction in transactions {
            mpt.insert(&transaction.hash().to_vec(), &transaction.encoded_2718())
                .await;
        }

        mpt.root_hash().await.unwrap()
    }

    pub async fn new(parent_hash: B256, block_number: u64, transactions: Vec<TxEnvelope>) -> Self {
        let tx_root = Self::calculate_transaction_root(&transactions).await;

        let mut header = Header::default();
        header.parent_hash = parent_hash;
        header.number = block_number;
        header.transactions_root = tx_root;
        header.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // let block_hash = B256::from_slice(&Keccak256::digest(
        //     &serde_json::to_vec(&header).unwrap_or_default(),
        // ));

        let mut block_body: BlockBody<TxEnvelope> = BlockBody::default();
        block_body.transactions = transactions;

        let block = Block::new(header, block_body);
        AppBlock(block)
    }

    pub async fn from_previous_block(
        &self,
        transactions: Vec<TxEnvelope>,
        state_root: B256,
    ) -> Self {
        let tx_root = Self::calculate_transaction_root(&transactions).await;

        let parent_hash = self.0.header.hash_slow();

        let mut header = Header::default();
        header.parent_hash = parent_hash;
        header.number = self.0.header.number + 1;
        header.transactions_root = tx_root;
        header.state_root = state_root;
        header.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut block_body: BlockBody<TxEnvelope> = BlockBody::default();
        block_body.transactions = transactions;

        let block = Block::new(header, block_body);
        AppBlock(block)
    }
}

pub struct AppChain {
    mempool: Receiver<TxEnvelope>,
    evm_db: Arc<RwLock<EvmDB>>,
    pub appchain_rpc: AppChainRPC,
    last_finalized_block: Option<B256>,
    last_produced_block: B256,
}

impl AppChain {
    pub async fn new() -> Self {
        let mut db = Arc::new(RwLock::new(EvmDB::new()));
        let mut db_write = db.write().await;

        let last_produced_block =
            if let Some(hash) = db_write.meta_db.get_last_last_produced_block().await {
                hash
            } else {
                let genesis_block = AppBlock::genesis_block();
                let hash = genesis_block.0.header.hash_slow();

                println!("{:?}", hash);

                println!("{:?}", genesis_block);
                db_write
                    .block_db
                    .insert_block(hash.to_vec(), genesis_block)
                    .await;
                hash
            };

        println!("last Produced block is {:?}", last_produced_block);

        let last_finalized_block = db_write.meta_db.get_last_finalized_block().await;

        drop(db_write);

        let (tx, rx) = mpsc::channel::<TxEnvelope>(100);

        AppChain {
            mempool: rx,
            evm_db: db.clone(),
            appchain_rpc: AppChainRPC::new(tx, db),
            last_finalized_block,
            last_produced_block,
        }
    }

    async fn save_produced_block(&mut self, block: AppBlock) {
        let mut db = self.evm_db.write().await;
        let block_hash = block.0.header.hash_slow();

        db.meta_db
            .set_number_to_block_hash(block.0.number, block_hash)
            .await;

        db.meta_db.set_last_last_produced_block(block_hash).await;

        db.meta_db
            .set_last_last_produced_block_number(block.0.number)
            .await;

        db.block_db.insert_block(block_hash.to_vec(), block).await;

        self.last_produced_block = block_hash;
    }

    async fn save_finalized_block(&mut self, hash: &B256) {
        let mut db = self.evm_db.write().await;

        db.meta_db.set_last_finalized_block(*hash).await;

        self.last_finalized_block = Some(*hash);
    }

    pub async fn process_tx_in_mempool(&mut self) {
        let mut transactions = Vec::with_capacity(10);
        for _ in 0..self.mempool.len() {
            if let Some(tx) = self.mempool.recv().await {
                transactions.push(tx);
            } else {
                break;
            }
        }

        let mut db = self.evm_db.write().await;

        // get last produced block
        let last_block = db
            .block_db
            .get_block(self.last_produced_block.to_vec())
            .await
            .unwrap_or(AppBlock::genesis_block());

        let mut state = if last_block.0.header.state_root.to_string() == EMPTY_TRIE_ROOT {
            EthTrie::new(db.account_db.clone())
        } else {
            // println!("{:?}", last_block.0.header.state_root);
            // create trie from last produced block root
            EthTrie::from(db.account_db.clone(), last_block.0.header.state_root)
                .await
                .unwrap()
        };

        // println!("Last block hash: {:?}", self.last_produced_block);
        // println!("Last block data: {:#?}", last_block);
        // println!("{:?}", last_block.0.header.state_root);
        // println!("tx will calculated");
        // apply transactions to state this logic will be done for creating finalized_block inside
        // zk circuit for a batch a transactions the batch transaction will come from a blocks that
        // is not been finalized
        let res = {
            let evm_db = WrapDatabaseAsync::new(&mut *db).unwrap();
            let ctx = Context::<BlockEnv, TxEnv, CfgEnv, WrapDatabaseAsync<&mut EvmDB>>::new(
                evm_db,
                SpecId::PRAGUE,
            );

            let mut evm = BlaceEvm::new(ctx, NoOpInspector);
            evm.0
                .transact_many_finalize(transactions.iter().map(|tx| MyTxEnv::from(tx).0))
                .unwrap()
        };

        let config = bincode::config::standard()
            .with_fixed_int_encoding()
            .with_big_endian();

        println!("evm result is {:#?}", res);
        for (k, v) in res.state.iter() {
            let account = if v.status.contains(AccountStatus::Created) {
                if let Some(code) = &v.info.code {
                    db.bytecode_db
                        .set_bytecode(v.info.code_hash, code.clone())
                        .await;
                };
                Account {
                    nonce: v.info.nonce,
                    balance: v.info.balance,
                    code_hash: v.info.code_hash,
                    storage_root: v.info.code_hash,
                }
            } else {
                let account = db
                    .account_db
                    .get_account(k, last_block.0.header.state_root)
                    .await
                    .unwrap();

                Account {
                    nonce: v.info.nonce,
                    balance: v.info.balance,
                    code_hash: account.code_hash,
                    storage_root: v.info.code_hash,
                }
            };

            //todo handle error case
            let mut storage = if let Ok(Some(s)) = db.storage_db.get_storage(k).await {
                s
            } else {
                HashMap::<StorageKey, StorageValue>::new()
            };
            for (k, v) in v.storage.iter() {
                storage.insert(*k, v.present_value);
            }
            db.storage_db.set_storage(k, storage).await;

            let binary_value = bincode::serde::encode_to_vec(&account, config).unwrap();
            state.insert(&k.into_array(), &binary_value).await;
            println!("account : {:?} is changed {:?}", k, v);
        }

        println!("tx is calculated");

        // saves all transactions and state transition to create new root and save block after that
        let root = state.root_hash_with_changed_nodes().await.unwrap();
        let root_hash = root.root;

        let block = last_block
            .from_previous_block(transactions, root_hash)
            .await;

        drop(db);
        self.save_produced_block(block).await;
    }

    pub async fn start(self) {
        let appchain = Arc::new(RwLock::new(self));
        let mut handles: Vec<JoinHandle<()>> = vec![];

        {
            let appchain = appchain.clone();
            handles.push(tokio::spawn(async move {
                let _ = appchain.write().await.appchain_rpc.start_rpc().await;
            }));
        }

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
            let mut interval = interval(Duration::from_secs(120));
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
