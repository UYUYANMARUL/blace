use alloy::primitives::B256;
use rusty_leveldb::{AsyncDB, Status, StatusCode, WriteBatch};
use serde::{de::DeserializeOwned, Serialize};
use std::{marker::PhantomData, sync::Arc};

use crate::mpt::EthTrie;
pub mod block_db;
pub mod mempool;
pub mod state_db;

impl crate::mpt::AsyncDB for rusty_leveldb::AsyncDB {
    type Error = Status;

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        <rusty_leveldb::AsyncDB>::get(self, key.to_vec()).await
    }

    async fn insert(&self, key: &[u8], value: Vec<u8>) -> Result<(), Self::Error> {
        self.put(key.to_vec(), value).await;
        Ok(())
    }

    async fn remove(&self, key: &[u8]) -> Result<(), Self::Error> {
        self.delete(key.to_vec()).await;
        Ok(())
    }

    async fn flush(&self) -> Result<(), Self::Error> {
        <AsyncDB>::flush(&self);
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

pub struct StateDB<T: Serialize + DeserializeOwned> {
    pub db: crate::mpt::EthTrie<AsyncDB>,
    _ty: PhantomData<T>,
}

impl<T> StateDB<T>
where
    T: Serialize + DeserializeOwned,
{
    async fn new(db: Arc<AsyncDB>, root: B256) -> Result<Self, anyhow::Error> {
        let eth_trie = EthTrie::from(db, root).await?;

        Ok(StateDB {
            db: eth_trie,
            _ty: PhantomData,
        })
    }
}

trait DefaultDb {
    type Item: Serialize + DeserializeOwned;

    async fn get(db: &AsyncDB, value: impl Into<Vec<u8>>) -> Option<Self::Item> {
        let config = bincode::config::standard()
            .with_fixed_int_encoding()
            .with_big_endian();

        let value = db.get(value.into()).await;

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

    async fn insert(
        db: &mut AsyncDB,
        key: impl Into<Vec<u8>>,
        value: Self::Item,
    ) -> Option<Self::Item> {
        let config = bincode::config::standard()
            .with_fixed_int_encoding()
            .with_big_endian();

        let binary_value = bincode::serde::encode_to_vec(&value, config).unwrap();
        let key = key.into();
        let _result = db.put(key.clone(), binary_value).await;

        Self::get(db, key).await
    }

    async fn flush(db: &mut AsyncDB) {
        db.flush().await;
    }

    async fn update_term(db: &mut AsyncDB, term: CurrentDbTerm) -> Result<u64, Status> {
        <CurrentDbTerm as DefaultDb>::insert(db, "currentterm".as_bytes().to_vec(), term)
            .await
            .ok_or_else(|| Status {
                code: StatusCode::AsyncError,
                err: "Wrong response type in AsyncDB.".to_string(),
            })
    }

    async fn get_term(db: &mut AsyncDB) -> Result<CurrentDbTerm, Status> {
        <CurrentDbTerm as DefaultDb>::get(db, "currentterm".as_bytes().to_vec())
            .await
            .ok_or_else(|| Status {
                code: StatusCode::AsyncError,
                err: "Wrong response type in AsyncDB.".to_string(),
            })
    }
}

type CurrentDbTerm = u64;

impl DefaultDb for CurrentDbTerm {
    type Item = CurrentDbTerm;
}
