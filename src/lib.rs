//! Rusty Socks - A lightweight WebSocket server implemented in Rust
//!
//! This library provides the core functionality for creating
//! a WebSocket server with client session management.

pub mod config;
pub mod constants;
pub mod core;
pub mod error;
pub mod handlers;
pub mod storage;

// Re-export main components
pub use config::*;
pub use constants::*;