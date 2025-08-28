use crate::db::{
    block_db::BlockHeadersDB, bytecode_db::BytecodeDB, state_db::AccountDB, storage_db::StorageDb,
};
use alloy::primitives::KECCAK256_EMPTY;
use revm::{
    database::async_db::DatabaseAsyncRef,
    primitives::{Address, U256},
    state::{Account, AccountInfo, Bytecode},
    DatabaseCommit,
};
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use alloy::primitives::map::foldhash::fast::RandomState;

pub struct EvmDB {
    storage_db: Arc<StorageDb>,
    bytecode_db: Arc<BytecodeDB>,
    block_db: Arc<BlockHeadersDB>,
    account_db: Arc<AccountDB>,
}

impl DatabaseCommit for EvmDB {
    #[doc = " Commit changes to the database."]
    fn commit(&mut self, changes: HashMap<Address, Account, RandomState>) {
        todo!()
    }
}

impl DatabaseAsyncRef for EvmDB {
    type Error = Infallible;

    fn basic_async_ref(
        &self,
        address: revm::primitives::Address,
    ) -> impl std::prelude::rust_2024::Future<
        Output = Result<Option<revm::state::AccountInfo>, Self::Error>,
    > + Send {
        async move {
            let account = self.account_db.get_account(address).await.unwrap().unwrap();
            let code = self.bytecode_db.get_code(account.code_hash).await.unwrap();
            Ok(Some(match code {
                Some(code) => AccountInfo::default()
                    .with_code_and_hash(code, account.code_hash)
                    .with_balance(account.balance)
                    .with_nonce(account.nonce),
                None => AccountInfo::default()
                    .with_code_hash(KECCAK256_EMPTY)
                    .with_balance(account.balance)
                    .with_nonce(account.nonce),
            }))
        }
    }

    fn code_by_hash_async_ref(
        &self,
        code_hash: revm::primitives::B256,
    ) -> impl std::prelude::rust_2024::Future<Output = Result<revm::state::Bytecode, Self::Error>> + Send
    {
        async move {
            Ok(self
                .bytecode_db
                .get_code(code_hash)
                .await
                .unwrap()
                .unwrap_or(Bytecode::default()))
        }
    }

    fn storage_async_ref(
        &self,
        address: revm::primitives::Address,
        index: revm::primitives::StorageKey,
    ) -> impl std::prelude::rust_2024::Future<
        Output = Result<revm::primitives::StorageValue, Self::Error>,
    > + Send {
        async move {
            let storage = self.storage_db.get_storage(address).await.unwrap().unwrap();
            Ok(*storage.get(&index).unwrap_or(&U256::ZERO))
        }
    }

    fn block_hash_async_ref(
        &self,
        number: u64,
    ) -> impl std::prelude::rust_2024::Future<Output = Result<revm::primitives::B256, Self::Error>> + Send
    {
        async move { todo!() }
    }
}
