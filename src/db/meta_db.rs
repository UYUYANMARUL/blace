use super::{DefaultDb, WrapperDefaultDB};
use revm::primitives::B256;
use rusty_leveldb::{AsyncDB, Options};
pub struct MetaDB {
    db: AsyncDB,
}

impl Default for MetaDB {
    fn default() -> Self {
        MetaDB::new()
    }
}

impl MetaDB {
    pub fn new() -> Self {
        Self {
            db: AsyncDB::new("meta", Options::default()).unwrap(),
        }
    }

    pub async fn get_block_hash_with_number(&self, number: u64) -> Option<B256> {
        WrapperDefaultDB::get(&self.db, number.to_be_bytes()).await
    }

    pub async fn set_number_to_block_hash(&mut self, number: u64, hash: B256) {
        WrapperDefaultDB::<B256>::insert(&mut self.db, number.to_be_bytes(), hash).await;
        WrapperDefaultDB::<B256>::flush(&mut self.db).await;
    }

    pub async fn get_last_last_produced_block_number(&self) -> Option<u64> {
        WrapperDefaultDB::get(&self.db, b"last_produced_block_number").await
    }

    pub async fn set_last_last_produced_block_number(&mut self, number: u64) {
        WrapperDefaultDB::<u64>::insert(&mut self.db, b"last_produced_block_number", number).await;
        WrapperDefaultDB::<u64>::flush(&mut self.db).await;
    }

    pub async fn get_last_last_produced_block(&self) -> Option<B256> {
        WrapperDefaultDB::get(&self.db, b"last_produced_block").await
    }

    pub async fn set_last_last_produced_block(&mut self, hash: B256) {
        WrapperDefaultDB::<B256>::insert(&mut self.db, b"last_produced_block", hash).await;
        WrapperDefaultDB::<B256>::flush(&mut self.db).await;
    }

    pub async fn get_last_finalized_block(&self) -> Option<B256> {
        WrapperDefaultDB::get(&self.db, b"last_finalized_block").await
    }

    pub async fn set_last_finalized_block(&mut self, hash: B256) {
        WrapperDefaultDB::<B256>::insert(&mut self.db, b"last_finalized_block", hash).await;
        WrapperDefaultDB::<B256>::flush(&mut self.db).await;
    }
}
