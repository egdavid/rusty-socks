//! Request handlers for different server endpoints

pub mod websocket;

// Re-export the websocket handler
pub use websocket::handle_ws_client;