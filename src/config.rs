//! Server configuration module
//! Handles dynamic configuration parameters for the WebSocket server

use std::env;
use std::time::Duration;
use crate::constants::{DEFAULT_HOST, DEFAULT_PORT, DEFAULT_THREAD_POOL_SIZE, DEFAULT_MAX_QUEUED_TASKS};

/// Server configuration parameters
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub buffer_size: usize,
    pub connection_timeout: Duration,
    pub ping_interval: Duration,
    /// Number of worker threads in the thread pool
    pub thread_pool_size: usize,
    /// Maximum number of tasks that can be queued
    pub max_queued_tasks: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            max_connections: 100,  // Default maximum number of simultaneous connections
            buffer_size: 1024,     // Default buffer size for messages
            connection_timeout: Duration::from_secs(60), // 1 minute timeout
            ping_interval: Duration::from_secs(30),      // 30 seconds ping interval
            thread_pool_size: DEFAULT_THREAD_POOL_SIZE,  // Default worker threads count
            max_queued_tasks: DEFAULT_MAX_QUEUED_TASKS,  // Default maximum queued tasks
        }
    }
}

impl ServerConfig {
    /// Load configuration from environment variables if available
    pub fn from_env() -> Self {
        let host = env::var("RUSTY_SOCKS_HOST").unwrap_or(DEFAULT_HOST.to_string());
        let port = env::var("RUSTY_SOCKS_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_PORT);

        let max_connections = env::var("RUSTY_SOCKS_MAX_CONN")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(100);

        let buffer_size = env::var("RUSTY_SOCKS_BUFFER")
            .ok()
            .and_then(|b| b.parse().ok())
            .unwrap_or(1024);

        let timeout_secs = env::var("RUSTY_SOCKS_TIMEOUT")
            .ok()
            .and_then(|t| t.parse().ok())
            .unwrap_or(60);

        let ping_secs = env::var("RUSTY_SOCKS_PING")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(30);

        let thread_pool_size = env::var("RUSTY_SOCKS_THREAD_POOL_SIZE")
            .ok()
            .and_then(|t| t.parse().ok())
            .unwrap_or(DEFAULT_THREAD_POOL_SIZE);

        let max_queued_tasks = env::var("RUSTY_SOCKS_MAX_QUEUED_TASKS")
            .ok()
            .and_then(|t| t.parse().ok())
            .unwrap_or(DEFAULT_MAX_QUEUED_TASKS);

        Self {
            host,
            port,
            max_connections,
            buffer_size,
            connection_timeout: Duration::from_secs(timeout_secs),
            ping_interval: Duration::from_secs(ping_secs),
            thread_pool_size,
            max_queued_tasks,
        }
    }
}