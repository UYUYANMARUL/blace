use crate::evm::database::EvmDB;
use crate::AppBlock;
use alloy::consensus::Account;
use alloy::consensus::Block;
use alloy::consensus::Header;
use alloy::consensus::TxEnvelope;
use alloy::rlp::{Decodable, Encodable};
use alloy_sol_types::sol;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use revm::primitives::Address;
use revm::primitives::{address, B256, U256};
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use tokio::sync::RwLock;

#[rpc(server, client, namespace = "eth")]
pub trait AppChain {
    #[method(name = "sendRawTransaction")]
    async fn eth_send_raw_transaction(&self, rlp_hex: String) -> Result<B256, ErrorObjectOwned>;

    #[method(name = "call")]
    async fn eth_call(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned>;

    #[method(name = "getTransactionReceipt")]
    async fn eth_get_transaction_receipt(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned>;

    #[method(name = "getTransactionCount")]
    async fn eth_get_transaction_count(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<u64, ErrorObjectOwned>;

    #[method(name = "getCode")]
    async fn eth_get_code(&self, address: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "blockNumber")]
    async fn eth_block_number(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "gasPrice")]
    async fn eth_gas_price(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "chainId")]
    async fn eth_chain_id(&self) -> Result<String, ErrorObjectOwned>;

    #[method(name = "getBlockByNumber")]
    async fn eth_get_block_by_number(
        &self,
        block: String,
        full_tx: bool,
    ) -> Result<JsonValue, ErrorObjectOwned>;

    #[method(name = "getBalance")]
    async fn eth_get_balance(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "getStorageAt")]
    async fn eth_get_storage_at(
        &self,
        address: String,
        position: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned>;

    #[method(name = "feeHistory")]
    async fn eth_fee_history(
        &self,
        block_count: String,
        newest_block: String,
        reward_percentiles: Option<Vec<f64>>,
    ) -> Result<JsonValue, ErrorObjectOwned>;

    // Non-standard methods (if these are custom)
    #[method(name = "getAccountInfo")]
    async fn eth_get_account_info(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<JsonValue, ErrorObjectOwned>;

    #[method(name = "getAccount")]
    async fn eth_get_account(&self, address: String) -> Result<JsonValue, ErrorObjectOwned>;
}

#[derive(Clone)]
pub struct AppChainRPC {
    tx: Sender<TxEnvelope>,
    evm_db: Arc<RwLock<EvmDB>>,
}

impl AppChainRPC {
    pub fn new(tx: Sender<TxEnvelope>, db: Arc<RwLock<EvmDB>>) -> Self {
        Self { tx, evm_db: db }
    }

    pub async fn start_rpc(&self) -> anyhow::Result<SocketAddr> {
        tracing::info!("Starting Blace server");
        let rpc = (*self).clone();
        let cors = tower::ServiceBuilder::new().layer(
            tower_http::cors::CorsLayer::new()
                .allow_methods([
                    hyper::Method::POST,
                    hyper::Method::GET,
                    hyper::Method::OPTIONS,
                ])
                .allow_headers([hyper::header::CONTENT_TYPE])
                .allow_origin(tower_http::cors::Any),
        );
        let server = Server::builder()
            .set_http_middleware(cors)
            .build("127.0.0.1:8000")
            .await?;
        let addr = server.local_addr()?;
        let handle = server.start(rpc.into_rpc());
        tracing::info!(
            address = %addr,
            ws_endpoint = %format!("ws://{}", addr),
            http_endpoint = %format!("http://{}", addr),
            "Blace server successfully started"
        );
        println!("🚀 Blace server started on {}", addr);
        println!("WebSocket endpoint: ws://{}", addr);
        println!("HTTP endpoint: http://{}", addr);
        tokio::spawn(handle.stopped());
        Ok(addr)
    }
}

#[async_trait]
impl AppChainServer for AppChainRPC {
    #[tracing::instrument(skip(self), fields(rlp_hex_len = rlp_hex.len()))]
    async fn eth_send_raw_transaction(&self, rlp_hex: String) -> Result<B256, ErrorObjectOwned> {
        tracing::info!("eth_sendRawTransaction");
        // Decode RLP transaction
        let rlp_bytes = hex::decode(rlp_hex.trim_start_matches("0x"))
            .map_err(|_| ErrorObjectOwned::owned(-32602, "Invalid RLP hex", None::<()>))?;

        let tx: TxEnvelope = TxEnvelope::decode(&mut rlp_bytes.as_slice()).map_err(|_| {
            ErrorObjectOwned::owned(-32602, "Failed to decode RLP transaction", None::<()>)
        })?;

        self.tx.send(tx.clone()).await.map_err(|_| {
            ErrorObjectOwned::owned(-32603, "Failed to send transaction", None::<()>)
        })?;

        // Calculate transaction hash
        let tx_hash_hex = format!("0x{:x}", tx.hash());
        tracing::info!(tx_hash = %tx_hash_hex, "Transaction hash calculated");

        Ok(*tx.hash())
    }

    async fn eth_call(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned> {
        tracing::info!("eth_call");
        todo!("eth_call: Implement call execution logic")
    }

    async fn eth_get_transaction_receipt(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned> {
        tracing::info!("eth_get_transaction_receipt");
        todo!("eth_getTransactionReceipt: Implement receipt retrieval logic")
    }

    async fn eth_get_transaction_count(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<u64, ErrorObjectOwned> {
        let addr: Address = address.parse().unwrap();

        let db = self.evm_db.read().await;

        let block_number: u64 = match block.as_deref() {
            Some("latest") => db
                .meta_db
                .get_last_last_produced_block_number()
                .await
                .expect("there should be some latest block"),
            Some(b) => u64::from_str_radix(b.trim_start_matches("0x"), 16).map_err(|x| {
                ErrorObjectOwned::owned(-32602, "Failed to parse block hash1", None::<()>)
            })?,
            None => db
                .meta_db
                .get_last_last_produced_block_number()
                .await
                .expect("there should be some latest block"),
        };

        tracing::info!(
            "eth_getTransactionCount called for address: {:?} and block : {:?}",
            addr,
            block
        );

        //todo handle error case if the input block number is incorrect
        let block_hash = db
            .meta_db
            .get_block_hash_with_number(block_number)
            .await
            .unwrap();

        //todo handle error case if the block is none
        let block = db.block_db.get_block(block_hash).await.unwrap();

        let block_state_root = block.0.state_root;

        let account = db.account_db.get_account(addr, block_state_root).await;

        match account {
            Some(account) => Ok(account.nonce),
            None => Ok(0),
        }
    }

    async fn eth_get_code(&self, address: String) -> Result<String, ErrorObjectOwned> {
        tracing::info!("eth_getCode called for address: {}", address);
        let addr: Address = address.parse().unwrap();
        let db = self.evm_db.read().await;

        let block_number: u64 = db
            .meta_db
            .get_last_last_produced_block_number()
            .await
            .expect("there should be some latest block");

        //todo handle error case if the input block number is incorrect
        let block_hash = db
            .meta_db
            .get_block_hash_with_number(block_number)
            .await
            .unwrap();

        //todo handle error case if the block is none
        let block = db.block_db.get_block(block_hash).await.unwrap();

        let block_state_root = block.0.state_root;

        let account = db.account_db.get_account(addr, block_state_root).await;

        let code = match account {
            Some(account) => db
                .bytecode_db
                .get_code(account.code_hash)
                .await
                .map_err(|x| {
                    ErrorObjectOwned::owned(
                        -32602,
                        "Failed to find block with that number",
                        None::<()>,
                    )
                })
                .map(|byte| {
                    byte.map_or("0x".to_string(), |bytecode| bytecode.bytecode().to_string())
                }),
            None => Ok("0x".to_string()),
        };

        println!("account is : {:?} {:?}", account, code);
        code
    }

    async fn eth_block_number(&self) -> Result<String, ErrorObjectOwned> {
        tracing::info!("eth_blockNumber called");
        let db = self.evm_db.read().await;
        let block_hash =
            db.meta_db
                .get_last_last_produced_block()
                .await
                .ok_or(ErrorObjectOwned::owned(
                    -32602,
                    "Failed to find block with that number",
                    None::<()>,
                ))?;

        let block = db
            .block_db
            .get_block(block_hash)
            .await
            .ok_or(ErrorObjectOwned::owned(
                -32602,
                "Failed to find block with that number",
                None::<()>,
            ))?;
        Ok(block.0.number.to_string())
    }

    async fn eth_gas_price(&self) -> Result<String, ErrorObjectOwned> {
        tracing::info!("eth_gasPrice called");
        // Return a default gas price (1 gwei = 0x3b9aca00)
        Ok("0x0".to_string())
    }

    async fn eth_chain_id(&self) -> Result<String, ErrorObjectOwned> {
        tracing::info!("eth_chainId called");
        // TODO: Return your actual chain ID (1337 for local dev)
        Ok("0x539".to_string())
    }

    async fn eth_get_block_by_number(
        &self,
        block: String,
        full_tx: bool,
    ) -> Result<JsonValue, ErrorObjectOwned> {
        tracing::info!("eth_getBlockByNumber called for block: {}", block);
        let db = self.evm_db.read().await;
        let num: u64 = match block.as_ref() {
            "latest" => db
                .meta_db
                .get_last_last_produced_block_number()
                .await
                .expect("there should be some latest block"),
            b => u64::from_str_radix(b.trim_start_matches("0x"), 16).map_err(|x| {
                ErrorObjectOwned::owned(-32602, "Failed to parse block hash1", None::<()>)
            })?,
        };

        let block_hash =
            db.meta_db
                .get_block_hash_with_number(num)
                .await
                .ok_or(ErrorObjectOwned::owned(
                    -32602,
                    "Failed to find block with that number",
                    None::<()>,
                ))?;

        let block = db
            .block_db
            .get_block(block_hash)
            .await
            .ok_or(ErrorObjectOwned::owned(
                -32602,
                "Failed to find block with that number",
                None::<()>,
            ))?;

        serde_json::to_value(&block.to_rpc_block()).map_err(|x| {
            ErrorObjectOwned::owned(-32602, "Failed to find block with that number", None::<()>)
        })
    }

    async fn eth_get_balance(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        tracing::info!("eth_getBalance called for address: {}", address);
        let addr: Address = address.parse().unwrap();
        let db = self.evm_db.read().await;

        let block_number: u64 = match block.as_deref() {
            Some("latest") => db
                .meta_db
                .get_last_last_produced_block_number()
                .await
                .expect("there should be some latest block"),
            Some(b) => u64::from_str_radix(b.trim_start_matches("0x"), 16).map_err(|x| {
                ErrorObjectOwned::owned(-32602, "Failed to parse block hash1", None::<()>)
            })?,
            None => db
                .meta_db
                .get_last_last_produced_block_number()
                .await
                .expect("there should be some latest block"),
        };

        tracing::info!("block number is: {}", block_number);

        //todo handle error case if the input block number is incorrect
        let block_hash = db
            .meta_db
            .get_block_hash_with_number(block_number)
            .await
            .unwrap();

        //todo handle error case if the block is none
        let block = db.block_db.get_block(block_hash).await.unwrap();

        let account = db.account_db.get_account(addr, block.0.state_root).await;

        match account {
            Some(a) => Ok(a.balance.to_string()),
            None => Ok("0x0".to_string()),
        }
    }

    async fn eth_get_storage_at(
        &self,
        address: String,
        position: String,
        block: Option<String>,
    ) -> Result<String, ErrorObjectOwned> {
        tracing::info!(
            "eth_getStorageAt called for address: {} at position: {}",
            address,
            position
        );

        let addr: Address = address.parse().unwrap();

        let db = self.evm_db.read().await;
        let storage = db.storage_db.get_storage(addr).await.map_err(|e| {
            ErrorObjectOwned::owned(-32602, "Failed to find storage with that hash", None::<()>)
        });

        match storage {
            // Ok(Some(st)) => Ok(st.get(position)),
            Ok(None) => Ok(
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            Err(e) => Err(ErrorObjectOwned::owned(
                -32602,
                "Failed to find storage with that hash",
                None::<()>,
            )),

            _ => Ok(
                "0x0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
        }
        // TODO: Implement actual storage retrieval from state
    }

    async fn eth_fee_history(
        &self,
        block_count: String,
        newest_block: String,
        reward_percentiles: Option<Vec<f64>>,
    ) -> Result<JsonValue, ErrorObjectOwned> {
        tracing::info!("eth_feeHistory called");
        Ok(serde_json::json!({
            "oldestBlock": "0x1",
            "baseFeePerGas": ["0x3b9aca00"],
            "gasUsedRatio": [0.0],
            "reward": [[]]
        }))
    }

    async fn eth_get_account_info(
        &self,
        address: String,
        block: Option<String>,
    ) -> Result<JsonValue, ErrorObjectOwned> {
        tracing::info!("eth_getAccountInfo called for address: {}", address);
        let addr: Address = address.parse().unwrap();
        let db = self.evm_db.read().await;

        tracing::info!("eth_get_account_info called for address: {}", address);
        tracing::info!("eth block hashasd {:?}", block);

        tracing::info!(
            "eth block hashasd {:?}",
            u64::from_str_radix(
                block
                    .clone()
                    .unwrap_or("0x".to_string())
                    .trim_start_matches("0x"),
                16
            )
        );

        let block_number: u64 = match block.as_deref() {
            Some("latest") => db
                .meta_db
                .get_last_last_produced_block_number()
                .await
                .expect("there should be some latest block"),
            Some(b) => u64::from_str_radix(b.trim_start_matches("0x"), 16).map_err(|x| {
                ErrorObjectOwned::owned(-32602, "Failed to parse block hash1", None::<()>)
            })?,
            None => db
                .meta_db
                .get_last_last_produced_block_number()
                .await
                .expect("there should be some latest block"),
        };

        tracing::info!("block number is: {}", block_number);

        //todo handle error case if the input block number is incorrect
        let block_hash = db
            .meta_db
            .get_block_hash_with_number(block_number)
            .await
            .unwrap();

        //todo handle error case if the block is none
        let block = db.block_db.get_block(block_hash).await.unwrap();

        let account = db
            .account_db
            .get_account(addr.clone(), block.0.state_root)
            .await
            .unwrap_or(Account::default());

        Ok(serde_json::json!({
            "address": address,
            "balance": account.balance,
            "nonce": account.nonce,
            "codeHash":account.code_hash
        }))
    }

    async fn eth_get_account(&self, address: String) -> Result<JsonValue, ErrorObjectOwned> {
        tracing::info!("eth_getAccount called for address: {}", address);
        // TODO: Implement account retrieval
        Ok(serde_json::json!({
            "address": address,
            "balance": "0x0",
            "nonce": "0x0"
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use crate::AppChain;

    use super::*;
    use alloy::consensus::{
        EthereumTypedTransaction, SignableTransaction, TxEip1559, TxEip4844Variant, TxEnvelope,
    };
    use alloy::network::{EthereumWallet, TransactionBuilder};
    use alloy::primitives::{Address, FixedBytes, U256 as AlloyU256};
    use alloy::rpc::types::{TransactionInput, TransactionRequest};
    use alloy::signers::local::PrivateKeySigner;
    use alloy_sol_types::SolCall;
    use jsonrpsee::core::client::ClientT;
    use revm::primitives::TxKind;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_rpc() -> anyhow::Result<()> {
        use BlaceContract::{create_blaceCall, place_pixelCall, BlaceContractCalls};

        // Smart contract function definitions
        sol! {
            // Contract address: 0x0000000000000000000000000000000000000000
            contract BlaceContract {
                function create_blace(bytes32 uuid, string memory name, uint256 size) external returns (bytes32 gameId);
                function place_pixel(bytes32 gameId, uint256 x, uint256 y, uint8 r, uint8 g, uint8 b) external returns (bool success);
            }
        }

        // Separate function to send transactions
        async fn send_tx(
            tx_request: TransactionRequest,
            wallet: &EthereumWallet,
            client: &jsonrpsee::ws_client::WsClient,
        ) -> anyhow::Result<String> {
            // Build the transaction
            let tx = EthereumTypedTransaction::<TxEip4844Variant>::from(
                tx_request.clone().build_1559()?,
            );

            // Sign transaction
            let mut unsigned_tx = tx_request.build_unsigned()?;
            let signed_tx = wallet
                .default_signer()
                .sign_transaction(&mut unsigned_tx)
                .await?;

            let tx_envelope = TxEnvelope::new_unhashed(tx, signed_tx);

            // Encode to RLP
            let mut rlp_bytes = Vec::new();
            tx_envelope.encode(&mut rlp_bytes);
            let rlp_hex = format!("0x{}", hex::encode(rlp_bytes));

            println!("Signed transaction (RLP): {}", rlp_hex);

            // Send transaction via RPC
            let tx_hash: String = client
                .request("eth_sendRawTransaction", jsonrpsee::rpc_params![rlp_hex])
                .await?;

            println!("Transaction hash: {}", tx_hash);
            Ok(tx_hash)
        }

        // Setup RPC client
        let url = format!("ws://127.0.0.1:8000");
        println!("Connecting to: {}", url);

        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await?;

        println!("Connected to RPC");

        // Create wallet
        let signer = PrivateKeySigner::from_str(
            "0xd342818b9833e1abe5f0bcb9991a01f84a7eb17df54019f768bd2cbf29a4eb8e",
        )?;
        let wallet = EthereumWallet::from(signer);
        let wallet_address = wallet.default_signer().address();
        println!("Wallet address: {}", wallet_address);

        let contract_address: Address = "0x0000000000000000000000000000000000000000".parse()?;

        let mut code: String = client
            .request("eth_getCode", jsonrpsee::rpc_params![contract_address])
            .await?;
        println!("Starting nonce: {}", code);

        // Get initial nonce
        let mut nonce: u64 = client
            .request(
                "eth_getTransactionCount",
                jsonrpsee::rpc_params![wallet_address],
            )
            .await?;
        println!("Starting nonce: {}", nonce);

        // // ========== Transaction 3: Create Blace Game ==========
        println!("\n=== Creating Blace Game ===");
        let create_call = BlaceContract::create_blaceCall {
            uuid: FixedBytes::default(),
            name: "Test Pixel Game".to_string(),
            size: AlloyU256::from(16),
        };
        let create_data = create_call.abi_encode();
        println!(
            "Create blace function data: 0x{}",
            hex::encode(&create_data)
        );

        let create_tx = TransactionRequest::default()
            .to(contract_address)
            .input(create_data.into())
            .gas_limit(100000)
            .max_fee_per_gas(10)
            .max_priority_fee_per_gas(10)
            .nonce(nonce);

        let create_hash = send_tx(create_tx, &wallet, &client).await?;
        println!("Created blace game with tx hash: {}", create_hash);
        nonce += 1;

        // Uncomment to send place pixel transaction
        // let pixel_hash = send_tx(, &wallet, &client).await?;
        // println!("Placed pixel withcreate_pixel_tx tx hash: {}", pixel_hash);

        Ok(())
    }
}
