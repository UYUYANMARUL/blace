use super::DefaultDb;
use crate::{db, AppBlock};
use alloy::consensus::{Header, TxEnvelope};
use alloy_rlp::{Decodable, Encodable};
use rusty_leveldb::{AsyncDB, Options};
pub struct BlockHeadersDB {
    db: AsyncDB,
}

impl BlockHeadersDB {
    pub fn new() -> Self {
        Self {
            db: AsyncDB::new("blockheaders", Options::default()).unwrap(),
        }
    }

    pub async fn get_block(&self, key: impl AsRef<[u8]>) -> Option<Header> {
        Self::get(&self.db, key).await
    }

    pub async fn insert_block(&mut self, key: impl AsRef<[u8]>, block: Header) -> Option<Header> {
        Self::insert(&mut self.db, key, block).await
    }
}

impl DefaultDb for BlockHeadersDB {
    type Item = Header;
}

pub struct BlockDataDB {
    db: AsyncDB,
}

impl BlockDataDB {
    pub fn new() -> Self {
        Self {
            db: AsyncDB::new("blocks", Options::default()).unwrap(),
        }
    }

    pub async fn get_block(&self, key: impl AsRef<[u8]>) -> Option<AppBlock> {
        let block = Self::get(&self.db, key).await?;
        Some(AppBlock::decode(&mut block.as_slice()).unwrap())
    }

    pub async fn insert_block(
        &mut self,
        key: impl AsRef<[u8]>,
        block: AppBlock,
    ) -> Option<AppBlock> {
        let mut encoded_block = Vec::<u8>::new();
        block.encode(&mut encoded_block);
        let data = Self::insert(&mut self.db, key, encoded_block).await?;
        Self::flush(&mut self.db).await;
        Some(AppBlock::decode(&mut data.as_slice()).unwrap())
    }
}

impl DefaultDb for BlockDataDB {
    type Item = Vec<u8>;
}
