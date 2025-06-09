//! Production mode warnings and security configuration validation
//! 
//! This module provides warnings for insecure configurations that should not be used in production.

use std::sync::Once;
use crate::security_logger::{log_security_event, SecurityEvent};

/// Initialize production mode warnings
static INIT: Once = Once::new();

/// Production warning types
#[derive(Debug, Clone)]
pub enum ProductionWarning {
    /// Development mode is enabled in production
    DevelopmentModeEnabled { component: String },
    /// Insecure default secrets being used
    InsecureDefaults { component: String, secret_type: String },
    /// Debug logging enabled in production
    DebugLoggingEnabled,
    /// TLS/SSL not properly configured
    InsecureTLS { reason: String },
    /// Rate limiting disabled or too permissive
    WeakRateLimiting { component: String },
    /// CSRF protection disabled
    CSRFDisabled,
    /// Authentication disabled for development
    AuthenticationDisabled,
    /// Default JWT secret in use
    DefaultJWTSecret,
    /// Missing environment variables for production
    MissingProductionConfig { variable: String },
}

/// Production environment detector
pub struct ProductionChecker {
    is_production: bool,
    environment: String,
}

impl ProductionChecker {
    /// Create a new production checker
    pub fn new() -> Self {
        let environment = std::env::var("RUST_ENV")
            .or_else(|_| std::env::var("ENVIRONMENT"))
            .or_else(|_| std::env::var("NODE_ENV"))
            .unwrap_or_else(|_| "development".to_string());
        
        let is_production = matches!(environment.to_lowercase().as_str(), 
            "production" | "prod" | "release"
        );
        
        Self {
            is_production,
            environment,
        }
    }
    
    /// Check if we're running in production
    pub fn is_production(&self) -> bool {
        self.is_production
    }
    
    /// Get the current environment
    pub fn environment(&self) -> &str {
        &self.environment
    }
    
    /// Log a production warning if in production mode
    pub async fn warn_if_production(&self, warning: ProductionWarning) {
        if self.is_production {
            let (component, message) = match &warning {
                ProductionWarning::DevelopmentModeEnabled { component } => {
                    (component.clone(), "Development mode is enabled in production environment".to_string())
                }
                ProductionWarning::InsecureDefaults { component, secret_type } => {
                    (component.clone(), format!("Insecure default {} detected in production", secret_type))
                }
                ProductionWarning::DebugLoggingEnabled => {
                    ("logging".to_string(), "Debug logging is enabled in production".to_string())
                }
                ProductionWarning::InsecureTLS { reason } => {
                    ("tls".to_string(), format!("TLS configuration issue: {}", reason))
                }
                ProductionWarning::WeakRateLimiting { component } => {
                    (component.clone(), "Rate limiting is disabled or too permissive for production".to_string())
                }
                ProductionWarning::CSRFDisabled => {
                    ("csrf".to_string(), "CSRF protection is disabled in production".to_string())
                }
                ProductionWarning::AuthenticationDisabled => {
                    ("auth".to_string(), "Authentication is disabled in production".to_string())
                }
                ProductionWarning::DefaultJWTSecret => {
                    ("jwt".to_string(), "Default JWT secret is being used in production".to_string())
                }
                ProductionWarning::MissingProductionConfig { variable } => {
                    ("config".to_string(), format!("Missing production configuration: {}", variable))
                }
            };
            
            log::error!("PRODUCTION WARNING: {} - {}", component, message);
            
            // Log to security event system
            log_security_event(SecurityEvent::ProductionModeWarning {
                component,
                warning: message,
            }).await;
        }
    }
    
    /// Perform comprehensive production readiness check
    pub async fn check_production_readiness(&self) -> Vec<ProductionWarning> {
        let mut warnings = Vec::new();
        
        if !self.is_production {
            return warnings; // Skip checks if not in production
        }
        
        // Check for development mode configurations
        if std::env::var("RUSTY_SOCKS_DEV_MODE").unwrap_or_default() == "true" {
            warnings.push(ProductionWarning::DevelopmentModeEnabled {
                component: "server".to_string(),
            });
        }
        
        // Check for default/insecure JWT secret
        if let Ok(jwt_secret) = std::env::var("RUSTY_SOCKS_JWT_SECRET") {
            if self.is_insecure_secret(&jwt_secret) {
                warnings.push(ProductionWarning::InsecureDefaults {
                    component: "jwt".to_string(),
                    secret_type: "JWT secret".to_string(),
                });
            }
        } else {
            warnings.push(ProductionWarning::MissingProductionConfig {
                variable: "RUSTY_SOCKS_JWT_SECRET".to_string(),
            });
        }
        
        // Check for default/insecure CSRF secret
        if let Ok(csrf_secret) = std::env::var("RUSTY_SOCKS_CSRF_SECRET") {
            if self.is_insecure_secret(&csrf_secret) {
                warnings.push(ProductionWarning::InsecureDefaults {
                    component: "csrf".to_string(),
                    secret_type: "CSRF secret".to_string(),
                });
            }
        } else {
            warnings.push(ProductionWarning::MissingProductionConfig {
                variable: "RUSTY_SOCKS_CSRF_SECRET".to_string(),
            });
        }
        
        // Check for debug logging
        if std::env::var("RUST_LOG").unwrap_or_default().contains("debug") ||
           std::env::var("RUST_LOG").unwrap_or_default().contains("trace") {
            warnings.push(ProductionWarning::DebugLoggingEnabled);
        }
        
        // Check TLS configuration
        if std::env::var("RUSTY_SOCKS_TLS_CERT").is_err() || 
           std::env::var("RUSTY_SOCKS_TLS_KEY").is_err() {
            warnings.push(ProductionWarning::InsecureTLS {
                reason: "TLS certificate or key not configured".to_string(),
            });
        }
        
        // Check rate limiting configuration
        if std::env::var("RUSTY_SOCKS_RATE_LIMIT_DISABLED").unwrap_or_default() == "true" {
            warnings.push(ProductionWarning::WeakRateLimiting {
                component: "rate_limiter".to_string(),
            });
        }
        
        // Log all warnings
        for warning in &warnings {
            self.warn_if_production(warning.clone()).await;
        }
        
        warnings
    }
    
    /// Check if a secret is insecure for production use
    fn is_insecure_secret(&self, secret: &str) -> bool {
        let insecure_patterns = [
            "test",
            "dev",
            "development",
            "example",
            "changeme",
            "password",
            "secret",
            "key",
            "default",
            "demo",
            "sample",
            "INSECURE-DEFAULT",
            "your-secret-key",
            "jwt-secret",
            "csrf-secret",
        ];
        
        let secret_lower = secret.to_lowercase();
        
        // Check for common insecure patterns
        for pattern in &insecure_patterns {
            if secret_lower.contains(pattern) {
                return true;
            }
        }
        
        // Check for too short secrets
        if secret.len() < 32 {
            return true;
        }
        
        // Check for obvious patterns (repeated characters, sequential)
        if secret.chars().all(|c| c == secret.chars().next().unwrap()) {
            return true; // All same character
        }
        
        if secret == "abcdefghijklmnopqrstuvwxyz" || 
           secret == "1234567890123456789012345678901234567890" {
            return true; // Sequential patterns
        }
        
        false
    }
}

/// Initialize production warnings and perform initial check
pub async fn init_production_warnings() {
    INIT.call_once(|| {
        log::info!("Initializing production security warnings...");
    });
    
    let checker = ProductionChecker::new();
    
    if checker.is_production() {
        log::warn!("PRODUCTION MODE DETECTED - Environment: {}", checker.environment());
        log::warn!("Performing production security readiness check...");
        
        let warnings = checker.check_production_readiness().await;
        
        if warnings.is_empty() {
            log::info!("✅ Production security check passed - no critical warnings found");
        } else {
            log::error!("❌ Production security check found {} warning(s)", warnings.len());
            log::error!("Please review and fix these issues before deploying to production");
        }
    } else {
        log::info!("Development mode detected - Environment: {}", checker.environment());
        log::info!("Production warnings will be shown if deployed to production");
    }
}

/// Get a global production checker instance
pub fn get_production_checker() -> ProductionChecker {
    ProductionChecker::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_insecure_secret_detection() {
        let checker = ProductionChecker::new();
        
        // These should be detected as insecure
        assert!(checker.is_insecure_secret("test"));
        assert!(checker.is_insecure_secret("password123"));
        assert!(checker.is_insecure_secret("your-secret-key"));
        assert!(checker.is_insecure_secret("short")); // Too short
        assert!(checker.is_insecure_secret("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")); // Repeated chars
        
        // These should be considered secure
        assert!(!checker.is_insecure_secret("a9b8c7d6e5f4g3h2i1j0k9l8m7n6o5p4q3r2s1t0u9v8w7x6y5z4"));
        assert!(!checker.is_insecure_secret("Kx9mP2nQ7rS8tU3vW6xY1zA4bC5dE8fG2hI9jK0lM3nO6pR7sT"));
    }
    
    #[test]
    fn test_production_detection() {
        // Test different environment variables
        std::env::set_var("RUST_ENV", "production");
        let checker = ProductionChecker::new();
        assert!(checker.is_production());
        
        std::env::set_var("RUST_ENV", "development");
        let checker = ProductionChecker::new();
        assert!(!checker.is_production());
        
        std::env::remove_var("RUST_ENV");
    }
}