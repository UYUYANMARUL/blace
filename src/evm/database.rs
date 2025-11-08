use crate::db::{
    block_db::{BlockDataDB, BlockHeadersDB},
    bytecode_db::BytecodeDB,
    meta_db::MetaDB,
    state_db::AccountDB,
    storage_db::StorageDb,
};
use alloy::primitives::KECCAK256_EMPTY;
use alloy::{consensus::Account as TrieAccount, primitives::map::foldhash::fast::RandomState};
use revm::{
    database::{async_db::DatabaseAsyncRef, DatabaseAsync},
    primitives::{Address, U256},
    state::{Account, AccountInfo, Bytecode},
    DatabaseCommit,
};
use std::{collections::HashMap, convert::Infallible, sync::Arc};

pub struct EvmDB {
    pub storage_db: StorageDb,
    pub bytecode_db: BytecodeDB,
    pub meta_db: MetaDB,
    pub account_db: Arc<AccountDB>,
    pub block_db: BlockDataDB,
}

impl EvmDB {
    pub fn new() -> Self {
        Self {
            storage_db: StorageDb::new(),
            bytecode_db: BytecodeDB::new(),
            meta_db: MetaDB::new(),
            account_db: Arc::new(AccountDB::new()),
            block_db: BlockDataDB::new(),
        }
    }
}

impl DatabaseAsync for &mut EvmDB {
    type Error = Infallible;

    async fn basic_async(
        &mut self,
        address: revm::primitives::Address,
    ) -> Result<Option<revm::state::AccountInfo>, Self::Error> {
        let block_hash = self.meta_db.get_last_last_produced_block().await.unwrap();
        let block = self.block_db.get_block(block_hash).await;

        let account = if let Some(account) = self
            .account_db
            .get_account(address, block.unwrap().0.state_root)
            .await
        {
            account
        } else {
            let mut new_accuont = TrieAccount::default();
            new_accuont.balance = U256::MAX;
            new_accuont
        };

        let code = self.bytecode_db.get_code(account.code_hash).await.unwrap();

        println!(
            "address {:?} acount code is {:#?},{:?} code {:?}",
            address,
            account.code_hash,
            account.code_hash.as_slice(),
            code
        );

        Ok(Some(match code {
            Some(code) => AccountInfo::default()
                .with_code_and_hash(code, account.code_hash)
                .with_balance(account.balance)
                .with_nonce(account.nonce),
            None => AccountInfo::default()
                .with_balance(account.balance)
                .with_nonce(account.nonce),
        }))
    }

    async fn code_by_hash_async(
        &mut self,
        code_hash: revm::primitives::B256,
    ) -> Result<revm::state::Bytecode, Self::Error> {
        let res = Ok(self
            .bytecode_db
            .get_code(code_hash)
            .await
            .unwrap()
            .unwrap_or(Bytecode::default()));

        println!(
            "acount code is {:#?},{:?} res is {:#?}",
            code_hash,
            code_hash.as_slice(),
            res
        );
        res
    }

    async fn storage_async(
        &mut self,
        address: revm::primitives::Address,
        index: revm::primitives::StorageKey,
    ) -> Result<revm::primitives::StorageValue, Self::Error> {
        let storage = self.storage_db.get_storage(address).await;
        match storage {
            Ok(Some(st)) => Ok(*st.get(&index).unwrap_or(&U256::ZERO)),
            _ => Ok(U256::ZERO),
        }
    }

    async fn block_hash_async(
        &mut self,
        number: u64,
    ) -> Result<revm::primitives::B256, Self::Error> {
        Ok(self
            .meta_db
            .get_block_hash_with_number(number)
            .await
            .unwrap())
    }
}
