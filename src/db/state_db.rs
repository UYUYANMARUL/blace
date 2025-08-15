// use std::sync::Arc;
//
// use crate::{
//     blockdata::block::BlockHeader,
//     crypto::ecdsa::PublicKeyK256,
//     mpt::{EthTrie, Trie, TrieResult},
// };
//
// use super::{DefaultDb, StateDB};
// use alloy_primitives::B256;
// use anyhow::Context;
// use rusty_leveldb::{AsyncDB, Options};
// use serde::{Deserialize, Serialize};
//
// #[derive(Serialize, Deserialize)]
// pub struct AccountStorage {
//     owner: PublicKeyK256,
//     amount: u128,
//     nonce: u64,
// }
//
// impl AccountStorage {
//     pub fn amount(&self) -> u128 {
//         self.amount
//     }
//     pub fn nonce(&self) -> u64 {
//         self.nonce
//     }
// }
//
// pub struct AccountDB {
//     db: Arc<AsyncDB>,
// }
//
// impl AccountDB {
//     pub fn new() -> Self {
//         Self {
//             db: Arc::new(AsyncDB::new("accounts", Options::default()).unwrap()),
//         }
//     }
//
//     pub async fn get_state_db_at(
//         &self,
//         root: B256,
//     ) -> Result<StateDB<AccountStorage>, anyhow::Error> {
//         StateDB::<AccountStorage>::new(self.db.clone(), root).await
//     }
// }
//
// impl StateDB<AccountStorage> {
//     pub async fn get_account_data(&self, key: impl Into<&[u8]>) -> Option<AccountStorage> {
//         let config = bincode::config::standard()
//             .with_fixed_int_encoding()
//             .with_big_endian();
//
//         let value = self.db.get(key.into()).await;
//
//         match value {
//             Ok(Some(value)) => Some(
//                 bincode::serde::decode_from_slice(&value, config)
//                     .map(|v| v.0)
//                     .unwrap(),
//             ),
//             Ok(None) => None,
//             Err(_e) => None,
//         }
//     }
//
//     pub async fn set_account_data(
//         &mut self,
//         key: impl Into<&[u8]>,
//         account: AccountStorage,
//     ) -> Result<AccountStorage, anyhow::Error> {
//         let key = key.into();
//         let config = bincode::config::standard()
//             .with_fixed_int_encoding()
//             .with_big_endian();
//
//         let binary_value = bincode::serde::encode_to_vec(&account, config).unwrap();
//
//         self.db.insert(key, &binary_value).await?;
//
//         Ok(Self::get_account_data(self, key).await.unwrap())
//     }
//
//     pub async fn get_account_proof(&mut self, key: impl Into<&[u8]>) -> Vec<Vec<u8>> {
//         self.db.get_proof(key.into()).await.unwrap()
//     }
//
//     pub async fn get_accounts_root(&mut self) -> B256 {
//         self.db.root_hash().await.unwrap()
//     }
//
//     pub async fn verify_accounts_root(
//         &self,
//         key: impl Into<&[u8]>,
//         root_hash: B256,
//         proof: Vec<Vec<u8>>,
//     ) -> TrieResult<Option<Vec<u8>>> {
//         self.db.verify_proof(root_hash, key.into(), proof).await
//     }
// }
