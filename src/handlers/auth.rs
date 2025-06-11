//! Authentication handlers for WebSocket connections

use std::time::Duration;
use warp::hyper::Uri;

use crate::auth::token::{extract_bearer_token, TokenManager};
use crate::auth::user::User;
use crate::error::Result;
use crate::security::AuthTimer;

/// Extract JWT token from WebSocket connection URL (REMOVED FOR SECURITY)
/// This function has been removed to prevent tokens from being exposed in URLs, logs, and referrer headers.
/// Use Authorization header, WebSocket subprotocol, or X-Auth-Token header instead.
pub fn extract_token_from_url(_uri: &Uri) -> Option<String> {
    log::error!("SECURITY: Token extraction from URL is disabled for security reasons");
    log::error!("Use Authorization header, WebSocket subprotocol, or X-Auth-Token header instead");
    None
}

/// Extract JWT token from WebSocket subprotocol header (SECURE)
pub fn extract_token_from_subprotocol(headers: &warp::hyper::HeaderMap) -> Option<String> {
    // Check for token in Sec-WebSocket-Protocol header
    // Format: "bearer.{jwt_token}" or "token.{jwt_token}"
    if let Some(protocol_header) = headers.get("sec-websocket-protocol") {
        if let Ok(protocol_str) = protocol_header.to_str() {
            for protocol in protocol_str.split(',') {
                let protocol = protocol.trim();
                if protocol.starts_with("bearer.") {
                    return Some(protocol[7..].to_string()); // Remove "bearer." prefix
                }
                if protocol.starts_with("token.") {
                    return Some(protocol[6..].to_string()); // Remove "token." prefix
                }
            }
        }
    }
    None
}

/// Secure token extraction from headers only
pub fn extract_token_comprehensive(
    _uri: &Uri,  // URI parameter no longer used for security reasons
    headers: &warp::hyper::HeaderMap
) -> Option<String> {
    // Priority 1: Authorization header (most secure)
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = extract_bearer_token(auth_str) {
                log::debug!("Token extracted from Authorization header");
                return Some(token);
            }
        }
    }
    
    // Priority 2: WebSocket subprotocol (secure)
    if let Some(token) = extract_token_from_subprotocol(headers) {
        log::debug!("Token extracted from WebSocket subprotocol");
        return Some(token);
    }
    
    // Priority 3: Custom header (acceptable)
    if let Some(custom_header) = headers.get("x-auth-token") {
        if let Ok(token_str) = custom_header.to_str() {
            log::debug!("Token extracted from X-Auth-Token header");
            return Some(token_str.to_string());
        }
    }
    
    // SECURITY: URL token extraction has been completely removed
    log::debug!("No token found in any secure headers");
    None
}

/// Authenticate a WebSocket connection using JWT token with enhanced security
pub async fn authenticate_connection(
    token: Option<String>,
    token_manager: &TokenManager,
    allow_anonymous: bool,
) -> Result<Option<User>> {
    let auth_timer = AuthTimer::new(Duration::from_millis(100)); // Minimum 100ms for auth
    match token {
        Some(token_str) => {
            // Additional token security validations
            if token_str.len() > 1000 {
                auth_timer.wait().await; // Ensure timing even on error
                return Err(crate::error::RustySocksError::AuthError(
                    "Token too long".to_string()
                ));
            }
            
            if token_str.chars().any(|c| c.is_control()) {
                auth_timer.wait().await; // Ensure timing even on error
                return Err(crate::error::RustySocksError::AuthError(
                    "Token contains invalid characters".to_string()
                ));
            }

            // Validate token and extract claims (includes revocation checking)
            let claims = match token_manager.get_claims(&token_str).await {
                Ok(claims) => claims,
                Err(e) => {
                    auth_timer.wait().await; // Ensure timing even on error
                    return Err(e);
                }
            };

            // Additional claims validation
            if claims.sub.is_empty() || claims.username.as_ref().map_or(true, |u| u.is_empty()) {
                auth_timer.wait().await; // Ensure timing even on error
                return Err(crate::error::RustySocksError::AuthError(
                    "Invalid token claims".to_string()
                ));
            }
            
            if claims.sub.len() > 100 || claims.username.as_ref().map_or(false, |u| u.len() > 50) {
                auth_timer.wait().await; // Ensure timing even on error
                return Err(crate::error::RustySocksError::AuthError(
                    "Token claims too long".to_string()
                ));
            }

            // Create user from claims with validation
            let mut user = User::new(claims.sub, claims.username.unwrap_or_else(|| "Unknown".to_string()));
            
            // Set a default global role for authenticated users
            user.global_role = Some(crate::auth::user::UserRole::Member);
            
            // Load full user data from database with proper role assignment in production

            auth_timer.wait().await; // Ensure minimum timing
            Ok(Some(user))
        }
        None => {
            auth_timer.wait().await; // Ensure consistent timing
            
            if allow_anonymous {
                // Anonymous connections are allowed with restricted permissions
                log::debug!("Anonymous WebSocket connection accepted (explicitly allowed)");
                Ok(None)
            } else {
                // SECURITY: Anonymous connections are disabled by default in production
                log::warn!("Anonymous WebSocket connection rejected: authentication required");
                Err(crate::error::RustySocksError::AuthError(
                    "Authentication required. Anonymous access is disabled.".to_string()
                ))
            }
        }
    }
}

/// Extract token from Authorization header
pub fn extract_token_from_header(auth_header: Option<&str>) -> Option<String> {
    auth_header.and_then(extract_bearer_token)
}

/// Validate origin header to prevent CSRF attacks
pub fn validate_origin(origin: Option<&str>, allowed_origins: &[String]) -> bool {
    match origin {
        Some(origin_value) => {
            // SECURITY: Require explicit origin configuration - no automatic localhost allowance
            if allowed_origins.is_empty() {
                log::warn!("No allowed origins configured, rejecting connection from: {}", origin_value);
                return false;
            }
            
            // Check against allowed origins list (exact match required)
            allowed_origins.iter().any(|allowed| origin_value == allowed)
        }
        None => {
            // SECURITY: Always reject connections without Origin header
            // This prevents certain CSRF attacks and ensures proper browser behavior
            log::warn!("WebSocket connection rejected: Missing Origin header");
            false
        }
    }
}

/// Validate origin header with development mode option
pub fn validate_origin_with_dev_mode(
    origin: Option<&str>, 
    allowed_origins: &[String], 
    development_mode: bool
) -> bool {
    match origin {
        Some(origin_value) => {
            // Check against allowed origins list first
            if allowed_origins.iter().any(|allowed| origin_value == allowed) {
                return true;
            }
            
            // SECURITY: Only allow localhost in explicit development mode
            if development_mode && allowed_origins.is_empty() {
                log::warn!("Development mode: allowing localhost origin: {}", origin_value);
                return origin_value.starts_with("http://localhost") || 
                       origin_value.starts_with("http://127.0.0.1") ||
                       origin_value.starts_with("https://localhost") ||
                       origin_value.starts_with("https://127.0.0.1");
            }
            
            log::warn!("Origin rejected: {} (not in allowed list)", origin_value);
            false
        }
        None => {
            // SECURITY: Always reject connections without Origin header
            log::warn!("WebSocket connection rejected: Missing Origin header");
            false
        }
    }
}

/// Validate WebSocket handshake for security
pub fn validate_websocket_handshake(
    origin: Option<&str>,
    user_agent: Option<&str>,
    allowed_origins: &[String],
) -> Result<()> {
    // Validate origin to prevent CSRF
    if !validate_origin(origin, allowed_origins) {
        log::warn!("WebSocket connection rejected: invalid origin {:?}", origin);
        return Err(crate::error::RustySocksError::Forbidden);
    }
    
    // Basic user agent validation (prevent obviously malicious bots)
    if let Some(ua) = user_agent {
        if ua.len() > 500 {
            log::warn!("WebSocket connection rejected: user agent too long");
            return Err(crate::error::RustySocksError::Forbidden);
        }
        
        // Block known malicious patterns
        let blocked_patterns = ["bot", "crawler", "spider", "scraper"];
        let ua_lower = ua.to_lowercase();
        if blocked_patterns.iter().any(|&pattern| ua_lower.contains(pattern)) {
            log::info!("WebSocket connection rejected: blocked user agent pattern");
            return Err(crate::error::RustySocksError::Forbidden);
        }
    }
    
    Ok(())
}
