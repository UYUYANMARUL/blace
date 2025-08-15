use alloy_sol_types::SolInterface;
use jsonrpsee::core::async_trait;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{PendingSubscriptionSink, Server};
use jsonrpsee::types::ErrorObjectOwned;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use alloy_rlp::Decodable;
use alloy_sol_types::sol;
use dashmap::DashMap;
use reth_primitives::TransactionSigned;
use secp256k1::Secp256k1;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

// Import the generated types
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
