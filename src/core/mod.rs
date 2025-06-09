//! Core functionality for the WebSocket server

pub mod broadcast_optimizer;
pub mod connection;
pub mod ip_extractor;
pub mod message;
pub mod message_handler;
pub mod message_types;
pub mod multi_tier_rate_limiter;
pub mod rate_limiter;
pub mod room;
pub mod server;
pub mod session;
pub mod thread_pool;

// Re-export main components for convenience
pub use connection::Connection;
pub use ip_extractor::{extract_client_ip, IpExtractionConfig};
pub use message::{Message, SocketMessage};
pub use message_handler::MessageHandler;
pub use message_types::{ClientMessage, RoomInfo, ServerMessage, UserInfo};
pub use multi_tier_rate_limiter::{MultiTierRateLimiter, UserTier, OperationType, RateLimitStatus};
pub use room::{Room, RoomManager};
pub use server::{ServerManager, SharedServerManager};
pub use session::SessionManager;
pub use thread_pool::{create_thread_pool, SharedThreadPool, ThreadPool};
