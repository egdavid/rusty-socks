//! Request handlers for different server endpoints

pub mod auth;
pub mod plugin;
pub mod token_management;
pub mod websocket;

// Re-export the websocket handler and plugin system
pub use plugin::{HandlerRegistry, HandlerResponse, MessageHandler, create_default_registry};
pub use websocket::handle_ws_client;
