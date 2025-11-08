use std::collections::HashMap;
use std::sync::Arc;

use crate::mpt::{EthTrie, Trie, TrieResult};

use super::{DefaultDb, StateDB};
use alloy::consensus::Account;
use alloy::primitives::StorageValue;
use alloy::primitives::B256;
use alloy::primitives::U256;
use anyhow::Context;
use bytes::Bytes;
use revm::bytecode::Bytecode;
use revm::primitives::StorageKey;
use rusty_leveldb::{AsyncDB, Options};
use serde::{Deserialize, Serialize};

pub type EvmStorageMap = HashMap<StorageKey, StorageValue>;

pub struct StorageDb {
    db: AsyncDB,
}

impl StorageDb {
    pub fn new() -> Self {
        Self {
            db: AsyncDB::new("storage", Options::default()).unwrap(),
        }
    }

    pub async fn get_storage(
        &self,
        key: impl AsRef<[u8]>,
    ) -> Result<Option<EvmStorageMap>, anyhow::Error> {
        Ok(Self::get(&self.db, key).await)
    }

    pub async fn set_storage(
        &mut self,
        key: impl AsRef<[u8]>,
        evm_storage_map: EvmStorageMap,
    ) -> Result<Option<EvmStorageMap>, anyhow::Error> {
        let data = Self::insert(&mut self.db, key, evm_storage_map).await;
        Self::flush(&mut self.db).await;
        Ok(data)
    }
}

impl Default for StorageDb {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultDb for StorageDb {
    type Item = EvmStorageMap;
}
