//! Core functionality for the WebSocket server

pub mod connection;
pub mod message;
pub mod message_handler;
pub mod message_types;
pub mod rate_limiter;
pub mod room;
pub mod server;
pub mod session;
pub mod thread_pool;

// Re-export main components for convenience
pub use connection::Connection;
pub use message::{Message, SocketMessage};
pub use message_handler::MessageHandler;
pub use message_types::{ClientMessage, RoomInfo, ServerMessage, UserInfo};
pub use room::{Room, RoomManager};
pub use server::{ServerManager, SharedServerManager};
pub use session::SessionManager;
pub use thread_pool::{create_thread_pool, SharedThreadPool, ThreadPool};
