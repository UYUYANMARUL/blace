use super::DefaultDb;
use crate::{db, Block, BlockHeader};
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

    pub async fn get_block(&self, key: impl AsRef<[u8]>) -> Option<BlockHeader> {
        Self::get(&self.db, key).await
    }

    pub async fn insert_block(
        &mut self,
        key: impl AsRef<[u8]>,
        block: BlockHeader,
    ) -> Option<BlockHeader> {
        Self::insert(&mut self.db, key, block).await
    }
}

impl DefaultDb for BlockHeadersDB {
    type Item = BlockHeader;
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

    pub async fn get_block(&self, key: impl AsRef<[u8]>) -> Option<Block> {
        Self::get(&self.db, key).await
    }

    pub async fn insert_block(&mut self, key: impl AsRef<[u8]>, block: Block) -> Option<Block> {
        let data = Self::insert(&mut self.db, key, block).await;
        Self::flush(&mut self.db).await;
        data
    }
}

impl DefaultDb for BlockDataDB {
    type Item = Block;
}
