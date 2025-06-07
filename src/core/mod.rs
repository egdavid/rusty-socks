//! Core functionality for the WebSocket server

pub mod connection;
pub mod message;
pub mod room;
pub mod session;
pub mod thread_pool;

// Re-export main components for convenience
pub use connection::Connection;
pub use message::{Message, SocketMessage};
pub use room::{Room, RoomManager};
pub use session::{create_session_manager, SessionManager, Sessions};
pub use thread_pool::{create_thread_pool, SharedThreadPool, ThreadPool};
