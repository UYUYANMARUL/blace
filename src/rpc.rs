use alloy::consensus::TxEnvelope;
use alloy::rlp::Decodable;
use alloy_sol_types::sol;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::Server;
use jsonrpsee::types::ErrorObjectOwned;
use revm::primitives::B256;
use std::net::SocketAddr;

#[rpc(server, client, namespace = "eth")]
pub trait AppChain {
    #[method(name = "sendRawTransaction")]
    async fn eth_send_raw_transaction(&self, rlp_hex: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_call")]
    async fn eth_call(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned>;

    #[method(name = "eth_getTransactionReceipt")]
    async fn eth_get_transaction_receipt(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned>;
}

#[derive(Debug, Clone)]
pub struct AppChainRPC {}

impl AppChainRPC {
    pub fn new() -> Self {
        Self {}
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

        println!("{:?}", tx);

        // Calculate transaction hash

        let tx_hash_hex = format!("0x{:x}", tx.hash());
        tracing::info!(tx_hash = %tx_hash_hex, "Transaction hash calculated");

        Ok(*tx.hash())
    }

    async fn eth_call(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned> {
        todo!()
    }

    async fn eth_get_transaction_receipt(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
    use alloy::network::{EthereumWallet, TransactionBuilder};
    use alloy::primitives::{Address, FixedBytes, U256 as AlloyU256};
    use alloy::rpc::types::TransactionRequest;
    use alloy::signers::local::PrivateKeySigner;
    use alloy_sol_types::SolCall;
    use jsonrpsee::core::client::ClientT;

    #[tokio::test]
    async fn test_rpc() -> anyhow::Result<()> {
        use BlaceContract::{create_blaceCall, place_pixelCall, BlaceContractCalls};
        // Smart contract function definitions
        sol! {
            // Contract address: 0x0000000000000000000000000000000000000000
            contract BlaceContract {
                function create_blace(string memory name, uint256 size) external returns (bytes32 gameId);
                function place_pixel(bytes32 gameId, uint256 x, uint256 y, uint8 r, uint8 g, uint8 b) external returns (bool success);
            }
        }

        let rpc = AppChainRPC::new();
        let server_addr = rpc.start_rpc().await?;
        let url = format!("ws://{}", server_addr);

        let client = jsonrpsee::ws_client::WsClientBuilder::default()
            .build(&url)
            .await?;

        // Create a test wallet using Alloy
        let signer = PrivateKeySigner::random();
        let wallet = EthereumWallet::from(signer);
        let wallet_address = wallet.default_signer().address();
        println!("Test wallet address: {}", wallet_address);

        let contract_address: Address = "0x0000000000000000000000000000000000000000".parse()?;

        // Create ABI-encoded function call for create_blace(string,uint256)
        let create_call = BlaceContract::create_blaceCall {
            name: "Test Pixel Game".to_string(),
            size: AlloyU256::from(16),
        };
        let create_data = create_call.abi_encode();

        println!("transaction data: {:?}", create_data);

        // Create transaction using Alloy
        let create_tx = TransactionRequest::default()
            .to(contract_address)
            .input(create_data.into())
            .gas_limit(100000)
            .nonce(0);

        println!("transaction: {:?}", create_tx);

        // Sign transaction
        let signed_create_tx = wallet
            .default_signer()
            .sign_transaction(&mut create_tx.build_unsigned()?)
            .await?;

        let create_envelope = TxEnvelope::Eip1559(signed_create_tx);

        // Encode to RLP
        let mut create_rlp_bytes = Vec::new();
        create_envelope.encode(&mut create_rlp_bytes);
        let create_rlp_hex = format!("0x{}", hex::encode(create_rlp_bytes));

        println!("Signed create transaction: {}", create_rlp_hex);
        println!(
            "Function selector for create_blace: 0x{}",
            hex::encode(&create_call.abi_encode()[0..4])
        );

        let tx_hash: String = client
            .request(
                "eth_sendRawTransaction",
                jsonrpsee::rpc_params![create_rlp_hex],
            )
            .await?;

        Ok(())
    }
}
