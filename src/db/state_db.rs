use std::sync::Arc;

use crate::mpt::{EthTrie, Trie, TrieResult};

use super::{DefaultDb, StateDB};
use alloy::consensus::Account;
use alloy::primitives::B256;
use alloy::primitives::U256;
use anyhow::Context;
use bytes::Bytes;
use rusty_leveldb::Status;
use rusty_leveldb::{AsyncDB, Options};
use serde::{Deserialize, Serialize};

pub struct AccountDB {
    db: Arc<AsyncDB>,
}

impl AccountDB {
    pub fn new() -> Self {
        Self {
            db: Arc::new(AsyncDB::new("accounts", Options::default()).unwrap()),
        }
    }

    pub async fn get_account(&self, key: impl AsRef<[u8]>, state_root: B256) -> Option<Account> {
        let state_db = EthTrie::from(self.db.clone(), state_root).await.unwrap();
        let value = state_db.get(key.as_ref()).await;
        let config = bincode::config::standard()
            .with_fixed_int_encoding()
            .with_big_endian();

        match value {
            Ok(Some(value)) => Some(
                bincode::serde::decode_from_slice(&value, config)
                    .map(|v| v.0)
                    .unwrap(),
            ),
            Ok(None) => None,
            Err(_e) => None,
        }
    }
}

impl Default for AccountDB {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::mpt::AsyncDB for AccountDB {
    type Error = Status;

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        <rusty_leveldb::AsyncDB>::get(&self.db, key.to_vec()).await
    }

    async fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.db.put(key.to_vec(), value).await;
        <AsyncDB>::flush(&self.db).await;
        Ok(())
    }

    async fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        self.db.delete(key.to_vec()).await;
        Ok(())
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        <AsyncDB>::flush(&self.db);
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> Result<usize, Self::Error> {
        todo!()
    }

    #[cfg(test)]
    fn is_empty(&self) -> Result<bool, Self::Error> {
        todo!()
    }
}

impl DefaultDb for AccountDB {
    type Item = Account;
}
