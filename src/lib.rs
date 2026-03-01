//! Rusty Socks - A lightweight WebSocket server implemented in Rust
//!
//! This library provides the core functionality for creating
//! a WebSocket server with client session management.
//!
//! When compiled for `wasm32-unknown-unknown`, exposes the Cloudflare Worker entry point
//! and the RustySocksState Durable Object. When compiled for native, exposes the usual
//! server library surface.

#[cfg(not(target_arch = "wasm32"))]
pub mod auth;
#[cfg(not(target_arch = "wasm32"))]
pub mod config;
#[cfg(not(target_arch = "wasm32"))]
pub mod constants;
#[cfg(not(target_arch = "wasm32"))]
pub mod core;
#[cfg(not(target_arch = "wasm32"))]
pub mod error;
#[cfg(not(target_arch = "wasm32"))]
pub mod handlers;
#[cfg(not(target_arch = "wasm32"))]
pub mod security;
#[cfg(not(target_arch = "wasm32"))]
pub mod security_logger;
#[cfg(not(target_arch = "wasm32"))]
pub mod storage;
#[cfg(not(target_arch = "wasm32"))]
pub mod tls;

#[cfg(target_arch = "wasm32")]
mod worker;

#[cfg(not(target_arch = "wasm32"))]
pub use config::*;
#[cfg(not(target_arch = "wasm32"))]
pub use constants::*;
