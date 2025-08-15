use alloy::primitives::B256;
use blace::{
    mpt::{EthTrie, MemoryDB, Trie, TrieError},
    AppChain,
};
use rusty_leveldb::{AsyncDB, Options};
use std::str::FromStr;
use std::sync::Arc;

#[tracing::instrument]
async fn run_server() -> anyhow::Result<()> {
    let appchain = AppChain::new().await;
    appchain.start().await;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter("blace=info,debug")
        .with_target(false)
        .with_thread_ids(true)
        .with_level(true)
        .init();

    tracing::info!("Blace application starting");

    let result = run_server().await;

    loop {}
}
