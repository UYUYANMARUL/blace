use std::sync::Arc;

use crate::mpt::{EthTrie, Trie, TrieResult};

use super::{DefaultDb, StateDB};
use alloy::consensus::Account;
use alloy::primitives::B256;
use alloy::primitives::U256;
use anyhow::Context;
use bytes::Bytes;
use revm::bytecode::Bytecode;
use rusty_leveldb::{AsyncDB, Options};
use serde::{Deserialize, Serialize};

pub struct BytecodeDB {
    db: AsyncDB,
}

impl BytecodeDB {
    pub fn new() -> Self {
        Self {
            db: AsyncDB::new("bytecodes", Options::default()).unwrap(),
        }
    }

    pub async fn get_code(&self, key: impl AsRef<[u8]>) -> Result<Option<Bytecode>, anyhow::Error> {
        Ok(Self::get(&self.db, key).await)
    }

    pub async fn set_bytecode(
        &mut self,
        key: impl AsRef<[u8]>,
        bytecode: Bytecode,
    ) -> Result<Option<Bytecode>, anyhow::Error> {
        let data = Self::insert(&mut self.db, key, bytecode).await;
        Self::flush(&mut self.db).await;
        Ok(data)
    }
}

impl DefaultDb for BytecodeDB {
    type Item = Bytecode;
}
