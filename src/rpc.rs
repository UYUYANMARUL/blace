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
                function transfer(address to, uint256 amount) external returns (bool);
                function mint(address to, uint256 amount) external returns (bool);
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

        // let mut code: String = client
        //     .request("eth_getCode", jsonrpsee::rpc_params![contract_address])
        //     .await?;
        // println!("Starting nonce: {}", code);

        // Get initial nonce
        let mut nonce: u64 = client
            .request(
                "eth_getTransactionCount",
                jsonrpsee::rpc_params![wallet_address],
            )
            .await?;
        println!("Starting nonce: {}", nonce);

        // // // ========== Transaction 3: Create Blace Game ==========
        // println!("\n=== Creating Blace Game ===");
        // let create_call = BlaceContract::create_blaceCall {
        //     uuid: FixedBytes::default(),
        //     name: "Test Pixel Game".to_string(),
        //     size: AlloyU256::from(16),
        // };
        // let create_data = create_call.abi_encode();
        // println!(
        //     "Create blace function data: 0x{}",
        //     hex::encode(&create_data)
        // );
        //
        //
        // let create_tx = TransactionRequest::default()
        //     .to(contract_address)
        //     .input(create_data.into())
        //     .gas_limit(100000)
        //     .max_fee_per_gas(10)
        //     .max_priority_fee_per_gas(10)
        //     .nonce(nonce);
        //
        // let create_hash = send_tx(create_tx, &wallet, &client).await?;
        // println!("Created blace game with tx hash: {}", create_hash);
        // nonce += 1;

        let contract_bytecode_hex = "610160806040523461054d57602081611b4d80380380916100208285610551565b83398101031261054d57516001600160a01b0381169081900361054d5760405161004b604082610551565b600481526020810163135554d160e21b81526040519161006c604084610551565b60098352680a6e8c2d6cac88aa8960bb1b602084015260405193610091604086610551565b6004855263135554d160e21b6020860152604051946100b1604087610551565b60018652603160f81b60208701908152855190956001600160401b0382116104505760035490600182811c92168015610543575b60208310146104325781601f8493116104d5575b50602090601f831160011461046f575f92610464575b50508160011b915f199060031b1c1916176003555b8051906001600160401b0382116104505760045490600182811c92168015610446575b60208310146104325781601f8493116103c4575b50602090601f831160011461035e575f92610353575b50508160011b915f199060031b1c1916176004555b801561034057600580546001600160a01b0319811683179091556001600160a01b03167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e05f80a36101d681610574565b610120526101e3846106fb565b61014052519020918260e05251902080610100524660a0526040519060208201927f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f8452604083015260608201524660808201523060a082015260a0815261024c60c082610551565b5190206080523060c052331561032d5760025469152d02c7e14af6800000810180911161031957600255335f525f60205260405f2069152d02c7e14af6800000815401905560405169152d02c7e14af680000081525f7fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef60203393a36040516113199081610834823960805181610e67015260a05181610f24015260c05181610e38015260e05181610eb601526101005181610edc0152610120518161053e015261014051816105670152f35b634e487b7160e01b5f52601160045260245ffd5b63ec442f0560e01b5f525f60045260245ffd5b631e4fbdf760e01b5f525f60045260245ffd5b015190505f80610171565b60045f9081528281209350601f198516905b8181106103ac5750908460019594939210610394575b505050811b01600455610186565b01515f1960f88460031b161c191690555f8080610386565b92936020600181928786015181550195019301610370565b60045f529091507f8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b601f840160051c81019160208510610428575b90601f859493920160051c01905b81811061041a575061015b565b5f815584935060010161040d565b90915081906103ff565b634e487b7160e01b5f52602260045260245ffd5b91607f1691610147565b634e487b7160e01b5f52604160045260245ffd5b015190505f8061010f565b60035f9081528281209350601f198516905b8181106104bd57509084600195949392106104a5575b505050811b01600355610124565b01515f1960f88460031b161c191690555f8080610497565b92936020600181928786015181550195019301610481565b60035f529091507fc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b601f840160051c81019160208510610539575b90601f859493920160051c01905b81811061052b57506100f9565b5f815584935060010161051e565b9091508190610510565b91607f16916100e5565b5f80fd5b601f909101601f19168101906001600160401b0382119082101761045057604052565b908151602081105f146105ee575090601f8151116105ae57602081519101516020821061059f571790565b5f198260200360031b1b161790565b604460209160405192839163305a27a960e01b83528160048401528051918291826024860152018484015e5f828201840152601f01601f19168101030190fd5b6001600160401b03811161045057600654600181811c911680156106f1575b602082101461043257601f81116106be575b50602092601f821160011461065d57928192935f92610652575b50508160011b915f199060031b1c19161760065560ff90565b015190505f80610639565b601f1982169360065f52805f20915f5b8681106106a6575083600195961061068e575b505050811b0160065560ff90565b01515f1960f88460031b161c191690555f8080610680565b9192602060018192868501518155019401920161066d565b60065f52601f60205f20910160051c810190601f830160051c015b8181106106e6575061061f565b5f81556001016106d9565b90607f169061060d565b908151602081105f14610726575090601f8151116105ae57602081519101516020821061059f571790565b6001600160401b03811161045057600754600181811c91168015610829575b602082101461043257601f81116107f6575b50602092601f821160011461079557928192935f9261078a575b50508160011b915f199060031b1c19161760075560ff90565b015190505f80610771565b601f1982169360075f52805f20915f5b8681106107de57508360019596106107c6575b505050811b0160075560ff90565b01515f1960f88460031b161c191690555f80806107b8565b919260206001819286850151815501940192016107a5565b60075f52601f60205f20910160051c810190601f830160051c015b81811061081e5750610757565b5f8155600101610811565b90607f169061074556fe6080806040526004361015610012575f80fd5b5f3560e01c90816306fdde031461092757508063095ea7b31461090157806318160ddd146108e457806323b872dd146108ac578063313ce567146108915780633644e5151461086f57806340c10f191461078e57806342966c681461077157806370a082311461072d578063715018a6146106af57806379cc67901461067f5780637ecebe001461063a57806384b0196e146105265780638da5cb5b146104f357806395d89b41146103f3578063a9059cbb146103c2578063d505accf1461022f578063dd62ed3e146101c15763f2fde38b146100ed575f80fd5b346101bd5760206003193601126101bd5773ffffffffffffffffffffffffffffffffffffffff61011b610a0c565b610123610ff4565b1680156101915773ffffffffffffffffffffffffffffffffffffffff600554827fffffffffffffffffffffffff0000000000000000000000000000000000000000821617600555167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e05f80a3005b7f1e4fbdf7000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b5f80fd5b346101bd5760406003193601126101bd576101da610a0c565b73ffffffffffffffffffffffffffffffffffffffff6101f7610a2f565b91165f52600160205273ffffffffffffffffffffffffffffffffffffffff60405f2091165f52602052602060405f2054604051908152f35b346101bd5760e06003193601126101bd57610248610a0c565b610250610a2f565b604435906064359260843560ff811681036101bd578442116103965761035161034873ffffffffffffffffffffffffffffffffffffffff9283851697885f52600860205260405f20908154916001830190556040519060208201927f6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c984528b6040840152878a1660608401528a608084015260a083015260c082015260c081526102fb60e082610b43565b519020610306610e21565b90604051917f190100000000000000000000000000000000000000000000000000000000000083526002830152602282015260c43591604260a4359220611171565b9092919261120b565b1684810361036657506103649350611041565b005b84907f4b800e46000000000000000000000000000000000000000000000000000000005f5260045260245260445ffd5b847f62791302000000000000000000000000000000000000000000000000000000005f5260045260245ffd5b346101bd5760406003193601126101bd576103e86103de610a0c565b6024359033610d2b565b602060405160018152f35b346101bd575f6003193601126101bd576040515f60045461041381610a52565b80845290600181169081156104b15750600114610453575b61044f8361043b81850382610b43565b6040519182916020835260208301906109c9565b0390f35b60045f9081527f8a35acfbc15ff81a39ae7d344fd709f28e8600b4aa8c65c6b64bfe7fe36bd19b939250905b8082106104975750909150810160200161043b61042b565b91926001816020925483858801015201910190929161047f565b7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff001660208086019190915291151560051b8401909101915061043b905061042b565b346101bd575f6003193601126101bd57602073ffffffffffffffffffffffffffffffffffffffff60055416604051908152f35b346101bd575f6003193601126101bd576105de6105627f00000000000000000000000000000000000000000000000000000000000000006110be565b61058b7f000000000000000000000000000000000000000000000000000000000000000061113a565b60206105ec6040519261059e8385610b43565b5f84525f3681376040519586957f0f00000000000000000000000000000000000000000000000000000000000000875260e08588015260e08701906109c9565b9085820360408701526109c9565b4660608501523060808501525f60a085015283810360c08501528180845192838152019301915f5b82811061062357505050500390f35b835185528695509381019392810192600101610614565b346101bd5760206003193601126101bd5773ffffffffffffffffffffffffffffffffffffffff610668610a0c565b165f526008602052602060405f2054604051908152f35b346101bd5760406003193601126101bd5761036461069b610a0c565b602435906106aa823383610bb1565b610f4a565b346101bd575f6003193601126101bd576106c7610ff4565b5f73ffffffffffffffffffffffffffffffffffffffff6005547fffffffffffffffffffffffff00000000000000000000000000000000000000008116600555167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e08280a3005b346101bd5760206003193601126101bd5773ffffffffffffffffffffffffffffffffffffffff61075b610a0c565b165f525f602052602060405f2054604051908152f35b346101bd5760206003193601126101bd5761036460043533610f4a565b346101bd5760406003193601126101bd576107a7610a0c565b73ffffffffffffffffffffffffffffffffffffffff16602435811561084357600254908082018092116108165760207fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef915f9360025584845283825260408420818154019055604051908152a3005b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b7fec442f05000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b346101bd575f6003193601126101bd576020610889610e21565b604051908152f35b346101bd575f6003193601126101bd57602060405160128152f35b346101bd5760606003193601126101bd576103e86108c8610a0c565b6108d0610a2f565b604435916108df833383610bb1565b610d2b565b346101bd575f6003193601126101bd576020600254604051908152f35b346101bd5760406003193601126101bd576103e861091d610a0c565b6024359033611041565b346101bd575f6003193601126101bd575f60035461094481610a52565b80845290600181169081156104b1575060011461096b5761044f8361043b81850382610b43565b60035f9081527fc2575a0e9e593c00f959f8c92f12db2869c3395a3b0502d05e2516446f71f85b939250905b8082106109af5750909150810160200161043b61042b565b919260018160209254838588010152019101909291610997565b907fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f602080948051918291828752018686015e5f8582860101520116010190565b6004359073ffffffffffffffffffffffffffffffffffffffff821682036101bd57565b6024359073ffffffffffffffffffffffffffffffffffffffff821682036101bd57565b90600182811c92168015610a99575b6020831014610a6c57565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b91607f1691610a61565b5f9291815491610ab283610a52565b8083529260018116908115610b075750600114610ace57505050565b5f9081526020812093945091925b838310610aed575060209250010190565b600181602092949394548385870101520191019190610adc565b905060209495507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0091509291921683830152151560051b010190565b90601f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0910116810190811067ffffffffffffffff821117610b8457604052565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b73ffffffffffffffffffffffffffffffffffffffff909291921691825f52600160205260405f2073ffffffffffffffffffffffffffffffffffffffff82165f5260205260405f2054927fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8403610c28575b50505050565b828410610ce1578015610cb55773ffffffffffffffffffffffffffffffffffffffff821615610c89575f52600160205273ffffffffffffffffffffffffffffffffffffffff60405f2091165f5260205260405f20910390555f808080610c22565b7f94280d62000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b7fe602df05000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b5073ffffffffffffffffffffffffffffffffffffffff83917ffb8f41b2000000000000000000000000000000000000000000000000000000005f521660045260245260445260645ffd5b73ffffffffffffffffffffffffffffffffffffffff16908115610df55773ffffffffffffffffffffffffffffffffffffffff1691821561084357815f525f60205260405f2054818110610dc357817fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef92602092855f525f84520360405f2055845f525f825260405f20818154019055604051908152a3565b827fe450d38c000000000000000000000000000000000000000000000000000000005f5260045260245260445260645ffd5b7f96c6fd1e000000000000000000000000000000000000000000000000000000005f525f60045260245ffd5b73ffffffffffffffffffffffffffffffffffffffff7f000000000000000000000000000000000000000000000000000000000000000016301480610f21575b15610e89577f000000000000000000000000000000000000000000000000000000000000000090565b60405160208101907f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f82527f000000000000000000000000000000000000000000000000000000000000000060408201527f000000000000000000000000000000000000000000000000000000000000000060608201524660808201523060a082015260a08152610f1b60c082610b43565b51902090565b507f00000000000000000000000000000000000000000000000000000000000000004614610e60565b90919073ffffffffffffffffffffffffffffffffffffffff168015610df557805f525f60205260405f2054838110610fc1576020845f94957fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef938587528684520360408620558060025403600255604051908152a3565b91507fe450d38c000000000000000000000000000000000000000000000000000000005f5260045260245260445260645ffd5b73ffffffffffffffffffffffffffffffffffffffff60055416330361101557565b7f118cdaa7000000000000000000000000000000000000000000000000000000005f523360045260245ffd5b73ffffffffffffffffffffffffffffffffffffffff16908115610cb55773ffffffffffffffffffffffffffffffffffffffff16918215610c895760207f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92591835f526001825260405f20855f5282528060405f2055604051908152a3565b60ff811461111d5760ff811690601f82116110f557604051916110e2604084610b43565b6020808452838101919036833783525290565b7fb3512b0c000000000000000000000000000000000000000000000000000000005f5260045ffd5b5060405161113781611130816006610aa3565b0382610b43565b90565b60ff811461115e5760ff811690601f82116110f557604051916110e2604084610b43565b5060405161113781611130816007610aa3565b91907f7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a08411611200579160209360809260ff5f9560405194855216868401526040830152606082015282805260015afa156111f5575f5173ffffffffffffffffffffffffffffffffffffffff8116156111eb57905f905f90565b505f906001905f90565b6040513d5f823e3d90fd5b5050505f9160039190565b60048110156112b6578061121d575050565b6001810361124d577ff645eedf000000000000000000000000000000000000000000000000000000005f5260045ffd5b6002810361128157507ffce698f7000000000000000000000000000000000000000000000000000000005f5260045260245ffd5b60031461128b5750565b7fd78bce0c000000000000000000000000000000000000000000000000000000005f5260045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602160045260245ffdfea264697066735822122040d76133f0509dfe42dd3800e256d87530b38826463c914d21d43fff8c17e38564736f6c634300081c00330000000000000000000000009a997cdd63535c64f2f265524aa744204c3015c0"; // Your bytecode without 0x prefix

        // Convert hex string to bytes
        let bytecode_bytes = hex::decode(contract_bytecode_hex)?;

        // Create TransactionInput from bytes
        let contract_input = TransactionInput::from(bytecode_bytes);

        let mut deploy_tx = TransactionRequest::default()
            .input(contract_input)
            .gas_limit(3000000)
            .max_fee_per_gas(10)
            .max_priority_fee_per_gas(10)
            .nonce(nonce);

        deploy_tx.set_create();

        // let deploy_hash = send_tx(deploy_tx, &wallet, &client).await?;
        // println!("Contract deployment tx hash: {}", deploy_hash);
        // nonce += 1;

        // Wait for deployment and get contract address
        sleep(Duration::from_secs(2)).await;

        // Calculate contract address (or get it from receipt)
        // For simplicity, using a known address - in production, calculate from deployer address and nonce
        let contract_address: Address = "0xc0e791ef2e526103370994ed920b6ec7edd8928b".parse()?;
        println!("Contract deployed at: {}", contract_address);

        // ========== Step 2: Mint Tokens ==========
        println!("\n=== Minting Tokens ===");
        let mint_amount = AlloyU256::from(1000000) * AlloyU256::from(10u64.pow(18)); // 1,000,000 tokens with 18 decimals

        let mint_call = BlaceContract::mintCall {
            to: wallet_address,
            amount: mint_amount,
        };
        let mint_data = mint_call.abi_encode();
        println!("Mint function data: 0x{}", hex::encode(&mint_data));

        let mint_tx = TransactionRequest::default()
            .to(contract_address)
            .input(mint_data.into())
            .gas_limit(100000)
            .max_fee_per_gas(10)
            .max_priority_fee_per_gas(10)
            .nonce(nonce);

        let mint_hash = send_tx(mint_tx, &wallet, &client).await?;
        println!("Minted tokens with tx hash: {}", mint_hash);
        nonce += 1;

        sleep(Duration::from_secs(2)).await;

        // ========== Step 3: Transfer Tokens ==========
        println!("\n=== Transferring Tokens ===");
        let recipient_address: Address = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".parse()?;
        let transfer_amount = AlloyU256::from(5000) * AlloyU256::from(10u64.pow(18)); // 10,000 tokens

        let transfer_call = BlaceContract::transferCall {
            to: recipient_address,
            amount: transfer_amount,
        };
        let transfer_data = transfer_call.abi_encode();
        println!("Transfer function data: 0x{}", hex::encode(&transfer_data));

        let transfer_tx = TransactionRequest::default()
            .to(contract_address)
            .input(transfer_data.into())
            .gas_limit(100000)
            .max_fee_per_gas(10)
            .max_priority_fee_per_gas(10)
            .nonce(nonce);

        let transfer_hash = send_tx(transfer_tx, &wallet, &client).await?;
        println!("Transferred tokens with tx hash: {}", transfer_hash);

        // Uncomment to send place pixel transaction
        // let pixel_hash = send_tx(, &wallet, &client).await?;
        // println!("Placed pixel withcreate_pixel_tx tx hash: {}", pixel_hash);

        Ok(())
    }
}
