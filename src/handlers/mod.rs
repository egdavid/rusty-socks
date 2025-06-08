//! Request handlers for different server endpoints

pub mod auth;
pub mod websocket;

// Re-export the websocket handler
pub use websocket::handle_ws_client;
