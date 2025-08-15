use alloy::consensus::TxEnvelope;
use alloy::consensus::TypedTransaction;
use alloy::rlp::Decodable;
use alloy_sol_types::sol;
use alloy_sol_types::SolInterface;
use dashmap::DashMap;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{PendingSubscriptionSink, Server};
use jsonrpsee::types::ErrorObjectOwned;
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

use BlaceContract::{create_blaceCall, place_pixelCall, BlaceContractCalls};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RgbColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PixelPosition {
    pub x: u32,
    pub y: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Game {
    pub id: Uuid,
    pub name: String,
    pub size: u32,
    pub pixels: HashMap<String, RgbColor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateBlaceRequest {
    pub name: String,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacePixelRequest {
    pub game_id: Uuid,
    pub position: PixelPosition,
    pub color: RgbColor,
    pub signature: String,
    pub user_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PixelChangeNotification {
    pub game_id: Uuid,
    pub position: PixelPosition,
    pub color: RgbColor,
    pub user_address: String,
    pub timestamp: u64,
}

type GameStorage = Arc<DashMap<Uuid, Game>>;
type PixelChangeNotifier = Arc<broadcast::Sender<PixelChangeNotification>>;

// Smart contract function definitions
sol! {
    // Contract address: 0x0000000000000000000000000000000000000000
    contract BlaceContract {
        function create_blace(string memory name, uint256 size) external returns (bytes32 gameId);
        function place_pixel(bytes32 gameId, uint256 x, uint256 y, uint8 r, uint8 g, uint8 b) external returns (bool success);
    }
}

#[rpc(server, client, namespace = "eth")]
pub trait AppChain {
    #[method(name = "sendRawTransaction")]
    async fn eth_send_raw_transaction(&self, rlp_hex: String) -> Result<String, ErrorObjectOwned>;

    #[method(name = "eth_call")]
    async fn eth_call(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned>;

    #[method(name = "eth_getTransactionReceipt")]
    async fn eth_get_transaction_receipt(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned>;

    #[method(name = "get_blace")]
    async fn get_blace(&self, game_id: String) -> Result<Game, ErrorObjectOwned>;

    #[subscription(name = "subscribe_pixel_changes", unsubscribe = "unsubscribe_pixel_changes", item = PixelChangeNotification)]
    async fn subscribe_pixel_changes(
        &self,
        game_id: Option<Uuid>,
    ) -> jsonrpsee::core::SubscriptionResult;
}

pub struct AppChainRPC {
    games: GameStorage,
    pixel_notifier: PixelChangeNotifier,
    secp: Secp256k1<secp256k1::All>,
}

impl AppChainRPC {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self {
            games: Arc::new(DashMap::new()),
            pixel_notifier: Arc::new(tx),
            secp: Secp256k1::new(),
        }
    }

    #[tracing::instrument(skip(self, tx))]
    fn decode_transaction_data(
        &self,
        tx: &TxEnvelope,
    ) -> Result<BlaceContractCalls, ErrorObjectOwned> {
        tracing::debug!("Decoding transaction data");
        let data = match tx {
            TxEnvelope::Legacy(signed) => &signed.tx().input,
            TxEnvelope::Eip2930(signed) => &signed.tx().input,
            TxEnvelope::Eip1559(signed) => &signed.tx().input,
            TxEnvelope::Eip4844(_) => {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    "EIP-4844 transactions not supported",
                    None::<()>,
                ));
            }
            TxEnvelope::Eip7702(signed) => &signed.tx().input,
        };

        if data.len() < 4 {
            return Err(ErrorObjectOwned::owned(
                -32602,
                "Invalid transaction data",
                None::<()>,
            ));
        }

        // Decode ABI-encoded function call
        let result = BlaceContractCalls::abi_decode(data).map_err(|e| {
            tracing::error!("Failed to decode ABI data: {}", e);
            ErrorObjectOwned::owned(
                -32602,
                format!("Failed to decode ABI data: {}", e),
                None::<()>,
            )
        });

        if result.is_ok() {
            tracing::debug!("Successfully decoded transaction data");
        }

        result
    }

    fn get_pixel_key(x: u32, y: u32) -> String {
        format!("{},{}", x, y)
    }

    pub async fn start_rpc(self) -> anyhow::Result<SocketAddr> {
        tracing::info!("Starting Blace server");
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
        let handle = server.start(self.into_rpc());
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
    async fn eth_send_raw_transaction(&self, rlp_hex: String) -> Result<String, ErrorObjectOwned> {
        tracing::info!("eth_sendRawTransaction");
        // Decode RLP transaction
        let rlp_bytes = hex::decode(rlp_hex.trim_start_matches("0x"))
            .map_err(|_| ErrorObjectOwned::owned(-32602, "Invalid RLP hex", None::<()>))?;

        let tx: TxEnvelope = TxEnvelope::decode(&mut rlp_bytes.as_slice()).map_err(|_| {
            ErrorObjectOwned::owned(-32602, "Failed to decode RLP transaction", None::<()>)
        })?;

        println!("{:?}", tx);

        // Calculate transaction hash
        let tx_hash = tx.hash();
        let tx_hash_hex = format!("0x{:x}", tx_hash);
        tracing::info!(tx_hash = %tx_hash_hex, "Transaction hash calculated");

        // Decode ABI-encoded contract call
        let contract_call = self.decode_transaction_data(&tx)?;

        match contract_call {
            BlaceContractCalls::create_blace(create_blaceCall { name, size }) => {
                let size: u32 = size.try_into().map_err(|_| {
                    ErrorObjectOwned::owned(-32602, "Invalid size value", None::<()>)
                })?;

                if size == 0 || size > 1000 {
                    return Err(ErrorObjectOwned::owned(-32602, "Invalid size", None::<()>));
                }

                let game = Game {
                    id: Uuid::new_v4(),
                    name: name.clone(),
                    size,
                    pixels: HashMap::new(),
                };

                tracing::info!(
                    game_id = %game.id,
                    game_name = %game.name,
                    game_size = game.size,
                    "Successfully created new blace game"
                );

                self.games.insert(game.id, game.clone());
            }

            BlaceContractCalls::place_pixel(place_pixelCall {
                gameId,
                x,
                y,
                r,
                g,
                b,
            }) => {
                // Convert bytes32 gameId to UUID
                let game_uuid_str = format!("{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                    gameId[0], gameId[1], gameId[2], gameId[3],
                    gameId[4], gameId[5], gameId[6], gameId[7],
                    gameId[8], gameId[9], gameId[10], gameId[11],
                    gameId[12], gameId[13], gameId[14], gameId[15]
                );
                let game_id = Uuid::parse_str(&game_uuid_str)
                    .map_err(|_| ErrorObjectOwned::owned(-32602, "Invalid game ID", None::<()>))?;

                let position = PixelPosition {
                    x: x.try_into().map_err(|_| {
                        ErrorObjectOwned::owned(-32602, "Invalid x position", None::<()>)
                    })?,
                    y: y.try_into().map_err(|_| {
                        ErrorObjectOwned::owned(-32602, "Invalid y position", None::<()>)
                    })?,
                };
                let color = RgbColor { r, g, b };

                // Recover signer address from transaction
                let recovered_address = match &tx {
                    TxEnvelope::Legacy(signed) => signed.recover_signer(),
                    TxEnvelope::Eip2930(signed) => signed.recover_signer(),
                    TxEnvelope::Eip1559(signed) => signed.recover_signer(),
                    TxEnvelope::Eip4844(signed) => signed.recover_signer(),
                    TxEnvelope::Eip7702(signed) => signed.recover_signer(),
                }
                .map_err(|_| {
                    ErrorObjectOwned::owned(-32602, "Failed to recover signer", None::<()>)
                })?;

                let user_address = format!("0x{:x}", recovered_address);
                // Get game and validate position
                let mut game = self
                    .games
                    .get_mut(&game_id)
                    .ok_or_else(|| ErrorObjectOwned::owned(-32602, "Game not found", None::<()>))?;

                if position.x >= game.size || position.y >= game.size {
                    return Err(ErrorObjectOwned::owned(
                        -32602,
                        "Invalid position",
                        None::<()>,
                    ));
                }

                // Update pixel
                let pixel_key = Self::get_pixel_key(position.x, position.y);
                game.pixels.insert(pixel_key, color.clone());

                tracing::info!(
                    game_id = %game_id,
                    x = position.x,
                    y = position.y,
                    r = color.r,
                    g = color.g,
                    b = color.b,
                    user_address = %user_address,
                    "Successfully placed pixel"
                );

                // Send notification
                let notification = PixelChangeNotification {
                    game_id,
                    position: position.clone(),
                    color: color.clone(),
                    user_address: user_address.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                };

                let _ = self.pixel_notifier.send(notification);
            }

            _ => {
                return Err(ErrorObjectOwned::owned(
                    -32602,
                    "Invalid function call for create_blace",
                    None::<()>,
                ));
            }
        };
        Ok(tx_hash_hex)
    }

    async fn eth_call(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned> {
        todo!()
    }

    async fn eth_get_transaction_receipt(&self, rlp_hex: String) -> Result<(), ErrorObjectOwned> {
        todo!()
    }

    async fn get_blace(&self, game_id: String) -> Result<Game, ErrorObjectOwned> {
        let game_uuid = Uuid::parse_str(&game_id)
            .map_err(|_| ErrorObjectOwned::owned(-32602, "Invalid game ID format", None::<()>))?;

        tracing::info!("Getting game: {}", game_uuid);

        let game = self
            .games
            .get(&game_uuid)
            .ok_or_else(|| ErrorObjectOwned::owned(-32602, "Game not found", None::<()>))?;

        Ok(game.clone())
    }

    async fn subscribe_pixel_changes(
        &self,
        sink: PendingSubscriptionSink,
        game_id: Option<Uuid>,
    ) -> jsonrpsee::core::SubscriptionResult {
        let sink = sink
            .accept()
            .await
            .map_err(|e| format!("Failed to accept subscription: {}", e))?;
        let mut receiver = self.pixel_notifier.subscribe();

        tokio::spawn(async move {
            while let Ok(notification) = receiver.recv().await {
                // Filter by game_id if specified
                if let Some(filter_game_id) = game_id {
                    if notification.game_id != filter_game_id {
                        continue;
                    }
                }

                use jsonrpsee::SubscriptionMessage;
                let msg = SubscriptionMessage::new(
                    "pixel_change",
                    uuid::Uuid::new_v4().to_string().into(),
                    &notification,
                )
                .unwrap();
                if sink.send(msg).await.is_err() {
                    break;
                }
            }
        });

        Ok(())
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

    #[tokio::test]
    async fn test_blace_contract_integration() -> anyhow::Result<()> {
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

        // Contract address (rollup backend)
        let contract_address: Address = "0x0000000000000000000000000000000000000000".parse()?;

        // Test 1: Create game via signed transaction
        println!("\n=== Testing Create Game via ABI-encoded Transaction ===");

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
            .nonce(0)
            .chain_id(1);

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

        println!("Create game transaction hash: {}", tx_hash);

        // For testing purposes, we'll create a known game ID that we can use
        let test_game_id = Uuid::new_v4();
        println!("Using test game ID: {}", test_game_id);

        // Test 2: Place pixel via signed transaction
        println!("\n=== Testing Place Pixel via ABI-encoded Transaction ===");

        // Convert UUID to bytes32 for the smart contract call
        let game_id_bytes = test_game_id.as_bytes();
        let mut padded_bytes = [0u8; 32];
        padded_bytes[..16].copy_from_slice(game_id_bytes);
        let game_id_fixed: FixedBytes<32> = FixedBytes::from(padded_bytes);

        // Create ABI-encoded function call for place_pixel
        let place_pixel_call = BlaceContract::place_pixelCall {
            gameId: game_id_fixed,
            x: AlloyU256::from(5),
            y: AlloyU256::from(8),
            r: 255,
            g: 0,
            b: 0,
        };

        let pixel_data = place_pixel_call.abi_encode();

        let pixel_tx = TransactionRequest::default()
            .to(contract_address)
            .input(pixel_data.into())
            .gas_limit(100000)
            .nonce(1)
            .chain_id(1);

        println!("pixel transaction: {:?}", pixel_tx);

        // Sign pixel transaction
        let signed_pixel_tx = wallet
            .default_signer()
            .sign_transaction(&mut pixel_tx.build_unsigned()?)
            .await?;
        let pixel_envelope = TxEnvelope::Eip1559(signed_pixel_tx);

        // Encode to RLP
        let mut pixel_rlp_bytes = Vec::new();
        pixel_envelope.encode(&mut pixel_rlp_bytes);
        let pixel_rlp_hex = format!("0x{}", hex::encode(pixel_rlp_bytes));

        println!("Signed pixel transaction: {}", pixel_rlp_hex);
        println!(
            "Function selector for place_pixel: 0x{}",
            hex::encode(&place_pixel_call.abi_encode()[0..4])
        );

        // Send pixel transaction via RPC
        let pixel_tx_hash: String = client
            .request(
                "eth_sendRawTransaction",
                jsonrpsee::rpc_params![pixel_rlp_hex],
            )
            .await?;

        println!("Pixel placement transaction hash: {}", pixel_tx_hash);

        // Test 3: Verify the game state
        println!("\n=== Verifying Game State ===");
        let final_game: Game = client
            .request(
                "get_blace",
                jsonrpsee::rpc_params![test_game_id.to_string()],
            )
            .await?;

        println!("Final game state:");
        println!("  ID: {}", final_game.id);
        println!("  Name: {}", final_game.name);
        println!("  Size: {}", final_game.size);
        println!("  Pixels count: {}", final_game.pixels.len());

        // Check if our pixel was placed correctly
        let pixel_key = "5,8";
        if let Some(placed_pixel) = final_game.pixels.get(pixel_key) {
            println!(
                "  Pixel at (5,8): r={}, g={}, b={}",
                placed_pixel.r, placed_pixel.g, placed_pixel.b
            );
            assert_eq!(placed_pixel.r, 255);
            assert_eq!(placed_pixel.g, 0);
            assert_eq!(placed_pixel.b, 0);
            println!("✅ All tests passed! ABI-encoded smart contract transaction processing works correctly.");
        } else {
            panic!("❌ Test failed: Pixel was not placed correctly");
        }

        Ok(())
    }
}
