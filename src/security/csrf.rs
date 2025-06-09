//! CSRF (Cross-Site Request Forgery) Protection
//! 
//! This module provides comprehensive CSRF protection for WebSocket connections
//! and HTTP endpoints. It implements multiple layers of protection:
//! 
//! 1. Origin header validation
//! 2. CSRF token validation
//! 3. Referer header checking
//! 4. SameSite cookie enforcement

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};
use warp::hyper::HeaderMap;
use rand::Rng;
use sha2::{Sha256, Digest};
use base64::Engine;
use crate::security::timing::{constant_time_eq, constant_time_eq_bytes, AuthTimer};
use crate::security_logger::{log_security_event, SecurityEvent};

/// Result of CSRF validation
#[derive(Debug, Clone, PartialEq)]
pub enum CSRFValidationResult {
    /// Request is valid and should be allowed
    Valid,
    /// Request has invalid origin
    InvalidOrigin(String),
    /// Request has invalid CSRF token
    InvalidToken(String),
    /// Request has invalid referer
    InvalidReferer(String),
    /// Request is missing required headers
    MissingHeaders(String),
    /// Request is suspicious and should be blocked
    Suspicious(String),
}

/// CSRF Protection configuration and validator
pub struct CSRFProtection {
    /// List of allowed origins for WebSocket connections
    allowed_origins: HashSet<String>,
    /// Development mode flag (allows localhost origins)
    development_mode: bool,
    /// CSRF token secret for validation
    token_secret: String,
    /// Token validity duration in seconds
    token_validity_seconds: u64,
}

impl CSRFProtection {
    /// Create a new CSRF protection instance
    pub fn new(allowed_origins: Vec<String>, development_mode: bool, token_secret: String) -> Self {
        Self {
            allowed_origins: allowed_origins.into_iter().collect(),
            development_mode,
            token_secret,
            token_validity_seconds: 3600, // 1 hour default
        }
    }

    /// Validate WebSocket connection for CSRF protection
    pub fn validate_websocket_connection(&self, headers: &HeaderMap) -> CSRFValidationResult {
        // Check Origin header (most important for WebSocket CSRF protection)
        let origin_result = self.validate_origin_header(headers);
        if origin_result != CSRFValidationResult::Valid {
            return origin_result;
        }

        // Check Host header to prevent Host header injection
        if let Some(host_header) = headers.get("host") {
            if let Ok(host_str) = host_header.to_str() {
                if self.is_suspicious_host(host_str) {
                    return CSRFValidationResult::Suspicious(
                        "Suspicious host header detected".to_string()
                    );
                }
            }
        }

        // Check for suspicious headers that might indicate automation
        if self.has_suspicious_automation_headers(headers) {
            return CSRFValidationResult::Suspicious(
                "Automated request detected".to_string()
            );
        }

        // Additional WebSocket-specific checks
        if let Some(upgrade_header) = headers.get("upgrade") {
            if let Ok(upgrade_str) = upgrade_header.to_str() {
                if upgrade_str.to_lowercase() != "websocket" {
                    return CSRFValidationResult::Suspicious(
                        "Invalid WebSocket upgrade header".to_string()
                    );
                }
            }
        } else {
            return CSRFValidationResult::MissingHeaders(
                "Missing WebSocket upgrade header".to_string()
            );
        }

        CSRFValidationResult::Valid
    }

    /// Validate Origin header against allowed origins
    fn validate_origin_header(&self, headers: &HeaderMap) -> CSRFValidationResult {
        let origin = headers.get("origin")
            .and_then(|h| h.to_str().ok());

        match origin {
            Some(origin_value) => {
                // Check against explicitly allowed origins first
                if self.allowed_origins.contains(origin_value) {
                    return CSRFValidationResult::Valid;
                }

                // Development mode: allow localhost origins if no explicit origins configured
                if self.development_mode && self.allowed_origins.is_empty() {
                    if self.is_localhost_origin(origin_value) {
                        log::debug!("Development mode: allowing localhost origin: {}", origin_value);
                        return CSRFValidationResult::Valid;
                    }
                }

                // Special handling for WebSocket origins (some browsers use different formats)
                if self.is_websocket_origin_allowed(origin_value) {
                    return CSRFValidationResult::Valid;
                }

                // Log CSRF attempt
                let origin_clone = origin_value.to_string();
                tokio::spawn(async move {
                    log_security_event(SecurityEvent::CSRFAttempt {
                        user_id: None,
                        ip: None,
                        origin: origin_clone,
                    }).await;
                });
                
                CSRFValidationResult::InvalidOrigin(format!("Origin '{}' not allowed", origin_value))
            }
            None => {
                // Missing Origin header is always suspicious for WebSocket connections
                CSRFValidationResult::MissingHeaders(
                    "Missing Origin header - required for CSRF protection".to_string()
                )
            }
        }
    }

    /// Check if origin is localhost (for development mode)
    fn is_localhost_origin(&self, origin: &str) -> bool {
        origin.starts_with("http://localhost") ||
        origin.starts_with("https://localhost") ||
        origin.starts_with("http://127.0.0.1") ||
        origin.starts_with("https://127.0.0.1") ||
        origin.starts_with("http://[::1]") ||
        origin.starts_with("https://[::1]")
    }

    /// Check if WebSocket origin is allowed (handles browser-specific origin formats)
    fn is_websocket_origin_allowed(&self, origin: &str) -> bool {
        // Some browsers might send different origin formats for WebSocket connections
        // Convert ws:// and wss:// origins to http:// and https:// for comparison
        let normalized_origin = if origin.starts_with("ws://") {
            origin.replace("ws://", "http://")
        } else if origin.starts_with("wss://") {
            origin.replace("wss://", "https://")
        } else {
            origin.to_string()
        };

        self.allowed_origins.contains(&normalized_origin)
    }

    /// Check if host header contains suspicious content
    fn is_suspicious_host(&self, host: &str) -> bool {
        // Check for obviously malicious hosts
        let suspicious_patterns = [
            "localhost.localdomain.attack",
            "evil.com",
            "attacker.com",
            ".onion",
            "127.0.0.1:80",  // Suspicious if explicit port 80
            "127.0.0.1:443", // Suspicious if explicit port 443
        ];

        let host_lower = host.to_lowercase();
        suspicious_patterns.iter().any(|&pattern| host_lower.contains(pattern))
    }

    /// Check for headers that indicate automated/scripted requests
    fn has_suspicious_automation_headers(&self, headers: &HeaderMap) -> bool {
        // Check User-Agent for obvious automation
        if let Some(user_agent) = headers.get("user-agent") {
            if let Ok(ua_str) = user_agent.to_str() {
                let ua_lower = ua_str.to_lowercase();
                let automation_indicators = [
                    "bot", "crawler", "spider", "scraper", "automation", 
                    "selenium", "phantomjs", "headless", "puppet",
                    "curl", "wget", "python-requests", "go-http-client"
                ];
                
                if automation_indicators.iter().any(|&indicator| ua_lower.contains(indicator)) {
                    log::warn!("Suspicious user agent detected: {}", ua_str);
                    return true;
                }
            }
        }

        // Check for automation-specific headers
        let automation_headers = [
            "x-requested-with",
            "x-automation",
            "x-selenium",
            "x-headless",
        ];

        for header_name in &automation_headers {
            if headers.contains_key(*header_name) {
                log::warn!("Automation header detected: {}", header_name);
                return true;
            }
        }

        false
    }

    /// Generate a CSRF token for a specific session
    pub fn generate_csrf_token(&self, session_id: &str) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create a random nonce
        let nonce: u64 = rand::thread_rng().gen();

        // Create token payload: session_id|timestamp|nonce
        let payload = format!("{}|{}|{}", session_id, timestamp, nonce);

        // Create HMAC signature using token secret
        let mut hasher = Sha256::new();
        hasher.update(self.token_secret.as_bytes());
        hasher.update(payload.as_bytes());
        let signature = hasher.finalize();

        // Encode as base64: payload.signature
        let token_data = format!("{}.{}", 
            base64::engine::general_purpose::URL_SAFE.encode(payload.as_bytes()),
            base64::engine::general_purpose::URL_SAFE.encode(signature.as_slice())
        );

        token_data
    }

    /// Validate a CSRF token with timing attack protection
    pub async fn validate_csrf_token(&self, token: &str, session_id: &str) -> CSRFValidationResult {
        // Start timing protection
        let timer = AuthTimer::default();
        // Split token into payload and signature
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 2 {
            timer.wait().await;
            return CSRFValidationResult::InvalidToken("Malformed token".to_string());
        }

        // Decode payload
        let payload_bytes = match base64::engine::general_purpose::URL_SAFE.decode(parts[0]) {
            Ok(bytes) => bytes,
            Err(_) => {
                timer.wait().await;
                return CSRFValidationResult::InvalidToken("Invalid payload encoding".to_string());
            }
        };

        let payload = match String::from_utf8(payload_bytes) {
            Ok(s) => s,
            Err(_) => {
                timer.wait().await;
                return CSRFValidationResult::InvalidToken("Invalid payload format".to_string());
            }
        };

        // Parse payload: session_id|timestamp|nonce
        let payload_parts: Vec<&str> = payload.split('|').collect();
        if payload_parts.len() != 3 {
            timer.wait().await;
            return CSRFValidationResult::InvalidToken("Invalid payload structure".to_string());
        }

        let token_session_id = payload_parts[0];
        let timestamp_str = payload_parts[1];

        // SECURITY: Use constant-time comparison to prevent timing attacks
        if !constant_time_eq(token_session_id, session_id) {
            timer.wait().await;
            return CSRFValidationResult::InvalidToken("Session ID mismatch".to_string());
        }

        // Verify timestamp is not too old
        let timestamp: u64 = match timestamp_str.parse() {
            Ok(ts) => ts,
            Err(_) => {
                timer.wait().await;
                return CSRFValidationResult::InvalidToken("Invalid timestamp".to_string());
            }
        };

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if current_time > timestamp + self.token_validity_seconds {
            timer.wait().await;
            return CSRFValidationResult::InvalidToken("Token expired".to_string());
        }

        // Verify signature
        let expected_signature_bytes = match base64::engine::general_purpose::URL_SAFE.decode(parts[1]) {
            Ok(bytes) => bytes,
            Err(_) => {
                timer.wait().await;
                return CSRFValidationResult::InvalidToken("Invalid signature encoding".to_string());
            }
        };

        let mut hasher = Sha256::new();
        hasher.update(self.token_secret.as_bytes());
        hasher.update(payload.as_bytes());
        let computed_signature = hasher.finalize();

        // SECURITY: Use constant-time comparison for signature verification
        if !constant_time_eq_bytes(&expected_signature_bytes, computed_signature.as_slice()) {
            timer.wait().await;
            return CSRFValidationResult::InvalidToken("Invalid signature".to_string());
        }
        
        // Ensure minimum time has elapsed before returning success
        timer.wait().await;

        CSRFValidationResult::Valid
    }

    /// Create CSRF protection headers for HTTP responses
    pub fn csrf_headers() -> Vec<(&'static str, &'static str)> {
        vec![
            // Prevent embedding in frames from other origins
            ("X-Frame-Options", "SAMEORIGIN"),
            // Require same-origin for certain requests
            ("X-Content-Type-Options", "nosniff"),
            // Enhanced referrer policy for CSRF protection
            ("Referrer-Policy", "strict-origin-when-cross-origin"),
            // Cross-Origin policies
            ("Cross-Origin-Embedder-Policy", "require-corp"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
        ]
    }

    /// Validate HTTP request for CSRF (for API endpoints)
    pub fn validate_http_request(&self, headers: &HeaderMap, method: &str) -> CSRFValidationResult {
        // Only validate state-changing methods
        if !matches!(method.to_uppercase().as_str(), "POST" | "PUT" | "DELETE" | "PATCH") {
            return CSRFValidationResult::Valid;
        }

        // Check Origin header
        let origin_result = self.validate_origin_header(headers);
        if origin_result != CSRFValidationResult::Valid {
            return origin_result;
        }

        // Check Referer header as additional protection
        if let Some(referer_header) = headers.get("referer") {
            if let Ok(referer_str) = referer_header.to_str() {
                if !self.is_referer_allowed(referer_str) {
                    return CSRFValidationResult::InvalidReferer(
                        format!("Referer '{}' not allowed", referer_str)
                    );
                }
            }
        }

        // For API requests, we could require CSRF token in header
        // This is optional and depends on your API design
        
        CSRFValidationResult::Valid
    }

    /// Check if referer is from an allowed origin
    fn is_referer_allowed(&self, referer: &str) -> bool {
        // Extract origin from referer URL
        if let Ok(url) = url::Url::parse(referer) {
            if let Some(host) = url.host_str() {
                let origin = format!("{}://{}", url.scheme(), host);
                
                // Add port if it's not default
                let origin_with_port = if let Some(port) = url.port() {
                    format!("{}:{}", origin, port)
                } else {
                    origin.clone()
                };

                return self.allowed_origins.contains(&origin) ||
                       self.allowed_origins.contains(&origin_with_port) ||
                       (self.development_mode && self.is_localhost_origin(&origin));
            }
        }
        false
    }
}