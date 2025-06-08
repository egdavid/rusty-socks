//! Authentication handlers for WebSocket connections

use std::collections::HashMap;
use warp::hyper::Uri;

use crate::auth::token::{extract_bearer_token, TokenManager};
use crate::auth::user::User;
use crate::error::Result;

/// Extract JWT token from WebSocket connection URL
pub fn extract_token_from_url(uri: &Uri) -> Option<String> {
    let query = uri.query()?;
    let params: HashMap<String, String> = query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.split('=');
            let key = parts.next()?;
            let value = parts.next()?;
            Some((key.to_string(), value.to_string()))
        })
        .collect();

    params.get("token").cloned()
}

/// Authenticate a WebSocket connection using JWT token with enhanced security
pub async fn authenticate_connection(
    token: Option<String>,
    token_manager: &TokenManager,
) -> Result<Option<User>> {
    match token {
        Some(token_str) => {
            // Additional token security validations
            if token_str.len() > 1000 {
                return Err(crate::error::RustySocksError::AuthError(
                    "Token too long".to_string()
                ));
            }
            
            if token_str.chars().any(|c| c.is_control()) {
                return Err(crate::error::RustySocksError::AuthError(
                    "Token contains invalid characters".to_string()
                ));
            }

            // Validate token and extract claims
            let claims = token_manager.get_claims(&token_str)?;

            // Additional claims validation
            if claims.sub.is_empty() || claims.username.is_empty() {
                return Err(crate::error::RustySocksError::AuthError(
                    "Invalid token claims".to_string()
                ));
            }
            
            if claims.sub.len() > 100 || claims.username.len() > 50 {
                return Err(crate::error::RustySocksError::AuthError(
                    "Token claims too long".to_string()
                ));
            }

            // Create user from claims with validation
            let mut user = User::new(claims.sub, claims.username);
            
            // Set a default global role for authenticated users
            user.global_role = Some(crate::auth::user::UserRole::Member);
            
            // TODO: Load full user data from database with proper role assignment

            Ok(Some(user))
        }
        None => {
            // Anonymous connections are allowed but with restricted permissions
            // This could be configurable for production environments
            log::debug!("Anonymous WebSocket connection accepted");
            Ok(None)
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
            // If no allowed origins specified, allow localhost for development
            if allowed_origins.is_empty() {
                return origin_value.starts_with("http://localhost") || 
                       origin_value.starts_with("http://127.0.0.1") ||
                       origin_value.starts_with("https://localhost") ||
                       origin_value.starts_with("https://127.0.0.1");
            }
            
            // Check against allowed origins list
            allowed_origins.iter().any(|allowed| origin_value == allowed)
        }
        None => {
            // No origin header - only allow if explicitly configured to do so
            // This is risky and should be avoided in production
            log::warn!("WebSocket connection attempt without Origin header");
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
