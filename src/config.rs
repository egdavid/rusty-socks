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
    /// CSRF secret for CSRF token generation/validation (separate from JWT for security)
    pub csrf_secret: String,
    /// Maximum connections per IP address
    pub max_connections_per_ip: usize,
    /// Rate limit: messages per minute per user
    pub rate_limit_messages_per_minute: u32,
    /// Allow anonymous connections (security consideration)
    pub allow_anonymous_access: bool,
    /// Development mode (enables localhost origins)
    pub development_mode: bool,
    /// TLS configuration
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    /// Enable TLS
    pub enable_tls: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        panic!("ServerConfig::default() is not allowed for security reasons. Use ServerConfig::from_env() instead.");
    }
}

impl ServerConfig {
    /// Create a test configuration - DANGEROUS: Only for testing!
    #[cfg(test)]
    pub fn for_testing() -> Self {
        Self {
            host: DEFAULT_HOST.to_string(),
            port: DEFAULT_PORT,
            max_connections: 100,
            buffer_size: 1024,
            connection_timeout: Duration::from_secs(60),
            ping_interval: Duration::from_secs(30),
            thread_pool_size: DEFAULT_THREAD_POOL_SIZE,
            max_queued_tasks: DEFAULT_MAX_QUEUED_TASKS,
            jwt_secret: "test-jwt-secret-only-for-unit-tests-never-use-in-production".to_string(),
            csrf_secret: "test-csrf-secret-only-for-unit-tests-never-use-in-production".to_string(),
            max_connections_per_ip: 10,
            rate_limit_messages_per_minute: 60,
            allow_anonymous_access: false,
            development_mode: true,
            tls_cert_path: None,
            tls_key_path: None,
            enable_tls: false,
        }
    }
    
    /// Validate that a secret meets security requirements
    fn validate_secret(secret: &str, secret_type: &str) -> Result<()> {
        if secret.len() < 32 {
            return Err(RustySocksError::ConfigError(
                format!("{} secret must be at least 32 characters long", secret_type)
            ));
        }
        
        // Check for insecure default or example values
        let insecure_patterns = [
            "your-secret-key",
            "change-this", 
            "INSECURE-DEFAULT-FOR-TESTING-ONLY",
            "INSECURE-CSRF-DEFAULT-FOR-TESTING-ONLY",
            "test-secret",
            "default",
            "secret",
            "password",
            "12345"
        ];
        
        for pattern in &insecure_patterns {
            if secret.contains(pattern) {
                return Err(RustySocksError::ConfigError(
                    format!("{} secret contains insecure pattern '{}'. Please use a secure random secret generated with: openssl rand -base64 32", secret_type, pattern)
                ));
            }
        }
        
        // Ensure some complexity
        if secret.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(RustySocksError::ConfigError(
                format!("{} secret should contain mixed characters (letters, numbers, symbols) for security", secret_type)
            ));
        }
        
        Ok(())
    }

    /// Validate JWT secret meets security requirements
    fn validate_jwt_secret(secret: &str) -> Result<()> {
        Self::validate_secret(secret, "JWT")
    }

    /// Validate CSRF secret meets security requirements
    fn validate_csrf_secret(secret: &str) -> Result<()> {
        Self::validate_secret(secret, "CSRF")
    }

    /// Ensure JWT and CSRF secrets are different for security
    fn validate_secrets_are_different(jwt_secret: &str, csrf_secret: &str) -> Result<()> {
        if jwt_secret == csrf_secret {
            return Err(RustySocksError::ConfigError(
                "JWT and CSRF secrets must be different for security. Using the same secret for both purposes increases attack surface.".to_string()
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
            .or_else(|_| env::var("JWT_SECRET"))
            .map_err(|_| {
                RustySocksError::ConfigError(
                    "JWT_SECRET environment variable is required for security. \
                     Generate one with: openssl rand -base64 32".to_string()
                )
            })?;

        let csrf_secret = env::var("RUSTY_SOCKS_CSRF_SECRET")
            .or_else(|_| env::var("CSRF_SECRET"))
            .map_err(|_| {
                RustySocksError::ConfigError(
                    "CSRF_SECRET environment variable is required for security. \
                     Generate one with: openssl rand -base64 32 \
                     NOTE: CSRF secret must be different from JWT secret.".to_string()
                )
            })?;

        let max_connections_per_ip = env::var("RUSTY_SOCKS_MAX_CONN_PER_IP")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(10);

        let rate_limit_messages = env::var("RUSTY_SOCKS_RATE_LIMIT_MSG_PER_MIN")
            .ok()
            .and_then(|r| r.parse().ok())
            .unwrap_or(60);

        let allow_anonymous_access = env::var("RUSTY_SOCKS_ALLOW_ANONYMOUS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false); // SECURITY: Default to false

        let development_mode = env::var("RUSTY_SOCKS_DEVELOPMENT_MODE")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false); // SECURITY: Default to false (production mode)

        // TLS configuration
        let enable_tls = env::var("RUSTY_SOCKS_ENABLE_TLS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let tls_cert_path = env::var("RUSTY_SOCKS_TLS_CERT_PATH").ok();
        let tls_key_path = env::var("RUSTY_SOCKS_TLS_KEY_PATH").ok();

        // Validate TLS configuration if enabled
        if enable_tls {
            if tls_cert_path.is_none() || tls_key_path.is_none() {
                return Err(RustySocksError::ConfigError(
                    "TLS is enabled but RUSTY_SOCKS_TLS_CERT_PATH or RUSTY_SOCKS_TLS_KEY_PATH is not set".to_string()
                ));
            }

            // Validate that certificate and key files exist
            if let (Some(ref cert_path), Some(ref key_path)) = (&tls_cert_path, &tls_key_path) {
                if !std::path::Path::new(cert_path).exists() {
                    return Err(RustySocksError::ConfigError(
                        format!("TLS certificate file does not exist: {}", cert_path)
                    ));
                }
                if !std::path::Path::new(key_path).exists() {
                    return Err(RustySocksError::ConfigError(
                        format!("TLS private key file does not exist: {}", key_path)
                    ));
                }
            }
        }

        // Validate both secrets
        Self::validate_jwt_secret(&jwt_secret)?;
        Self::validate_csrf_secret(&csrf_secret)?;
        Self::validate_secrets_are_different(&jwt_secret, &csrf_secret)?;

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
            csrf_secret,
            max_connections_per_ip,
            rate_limit_messages_per_minute: rate_limit_messages,
            allow_anonymous_access,
            development_mode,
            enable_tls,
            tls_cert_path,
            tls_key_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    #[should_panic(expected = "ServerConfig::default() is not allowed for security reasons")]
    fn test_default_panics() {
        let _ = ServerConfig::default();
    }
    
    #[test]
    fn test_for_testing_works_in_tests() {
        let config = ServerConfig::for_testing();
        assert!(config.jwt_secret.contains("test"));
        assert!(config.csrf_secret.contains("test"));
        assert!(config.development_mode);
    }
    
    #[test]
    fn test_from_env_requires_secrets() {
        // Clear any existing env vars
        env::remove_var("RUSTY_SOCKS_JWT_SECRET");
        env::remove_var("JWT_SECRET");
        env::remove_var("RUSTY_SOCKS_CSRF_SECRET");
        env::remove_var("CSRF_SECRET");
        
        let result = ServerConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("JWT_SECRET"));
    }
}
