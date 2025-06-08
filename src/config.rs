//! Server configuration module
//! Handles dynamic configuration parameters for the WebSocket server

use crate::constants::{
    DEFAULT_HOST, DEFAULT_MAX_QUEUED_TASKS, DEFAULT_PORT, DEFAULT_THREAD_POOL_SIZE,
};
use crate::error::{Result, RustySocksError};
use std::env;
use std::time::Duration;

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
    /// JWT secret for token signing/validation
    pub jwt_secret: String,
    /// Maximum connections per IP address
    pub max_connections_per_ip: usize,
    /// Rate limit: messages per minute per user
    pub rate_limit_messages_per_minute: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            max_connections: 100, // Default maximum number of simultaneous connections
            buffer_size: 1024,    // Default buffer size for messages
            connection_timeout: Duration::from_secs(60), // 1 minute timeout
            ping_interval: Duration::from_secs(30), // 30 seconds ping interval
            thread_pool_size: DEFAULT_THREAD_POOL_SIZE, // Default worker threads count
            max_queued_tasks: DEFAULT_MAX_QUEUED_TASKS, // Default maximum queued tasks
            jwt_secret: Self::generate_secure_secret(),
            max_connections_per_ip: 10,     // Default 10 connections per IP
            rate_limit_messages_per_minute: 60, // Default 60 messages per minute
        }
    }
}

impl ServerConfig {
    /// Generate a cryptographically secure random JWT secret
    fn generate_secure_secret() -> String {
        use rand::RngCore;
        use base64::Engine;
        
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
    
    /// Validate JWT secret meets security requirements
    fn validate_jwt_secret(secret: &str) -> Result<()> {
        if secret.len() < 32 {
            return Err(RustySocksError::ConfigError(
                "JWT secret must be at least 32 characters long".to_string()
            ));
        }
        
        if secret.contains("your-secret-key") || secret.contains("change-this") {
            return Err(RustySocksError::ConfigError(
                "JWT secret appears to be a default/example value. Please use a secure random secret.".to_string()
            ));
        }
        
        Ok(())
    }

    /// Load configuration from environment variables if available
    pub fn from_env() -> Result<Self> {
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

        let jwt_secret = env::var("RUSTY_SOCKS_JWT_SECRET")
            .unwrap_or_else(|_| {
                eprintln!("WARNING: RUSTY_SOCKS_JWT_SECRET not set. Generating random secret.");
                eprintln!("WARNING: This secret will change on each restart, invalidating existing tokens.");
                eprintln!("WARNING: For production, set RUSTY_SOCKS_JWT_SECRET environment variable.");
                Self::generate_secure_secret()
            });

        let max_connections_per_ip = env::var("RUSTY_SOCKS_MAX_CONN_PER_IP")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(10);

        let rate_limit_messages = env::var("RUSTY_SOCKS_RATE_LIMIT_MSG_PER_MIN")
            .ok()
            .and_then(|r| r.parse().ok())
            .unwrap_or(60);

        // Validate the JWT secret
        Self::validate_jwt_secret(&jwt_secret)?;

        Ok(Self {
            host,
            port,
            max_connections,
            buffer_size,
            connection_timeout: Duration::from_secs(timeout_secs),
            ping_interval: Duration::from_secs(ping_secs),
            thread_pool_size,
            max_queued_tasks,
            jwt_secret,
            max_connections_per_ip,
            rate_limit_messages_per_minute: rate_limit_messages,
        })
    }
}
