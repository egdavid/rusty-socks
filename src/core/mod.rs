//! Core functionality for the WebSocket server

pub mod connection;
pub mod message;
pub mod session;

// Re-export main components for convenience
pub use connection::Connection;
pub use message::{Message, SocketMessage};
pub use session::{SessionManager, Sessions, create_session_manager};