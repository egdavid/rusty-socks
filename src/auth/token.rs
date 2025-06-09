use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use uuid::Uuid;

use crate::error::{Result, RustySocksError};
use crate::storage::token_revocation::{SharedTokenRevocationStore, RevokedToken, RevocationReason};
use crate::security::timing::AuthTimer;
use crate::security_logger::{log_security_event, SecurityEvent};

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Username
    pub username: Option<String>,
    /// Expiration time (as UTC timestamp)
    pub exp: usize,
    /// Issued at (as UTC timestamp)
    pub iat: usize,
    /// Not before (as UTC timestamp)
    pub nbf: usize,
    /// Optional email
    pub email: Option<String>,
    /// Issuer
    pub iss: Option<String>,
    /// Audience
    pub aud: Option<String>,
    /// JWT ID for token identification and revocation
    pub jti: Option<String>,
}

impl Claims {
    /// Creates new claims for a user
    pub fn new(user_id: String, username: String, email: Option<String>) -> Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RustySocksError::SystemError("System time error: time went backwards".to_string()))?
            .as_secs() as usize;

        Ok(Self {
            sub: user_id,
            username: Some(username),
            exp: now + 86400, // 24 hours from now
            iat: now,
            nbf: now,
            email,
            iss: None,
            aud: None,
            jti: Some(Uuid::new_v4().to_string()), // Generate unique JWT ID
        })
    }

    /// Creates claims with custom expiration
    pub fn with_expiration(
        user_id: String,
        username: String,
        email: Option<String>,
        hours: usize,
    ) -> Result<Self> {
        let mut claims = Self::new(user_id, username, email)?;
        let now = claims.iat;
        claims.exp = now + (hours * 3600);
        Ok(claims)
    }
    
    /// Get a unique identifier for this token (for revocation purposes)
    pub fn get_token_id(&self) -> String {
        self.jti.clone().unwrap_or_else(|| {
            // Fallback: generate ID from token contents if jti is missing
            let mut hasher = Sha256::new();
            hasher.update(format!("{}_{}_{}", self.sub, self.iat, self.exp));
            format!("{:x}", hasher.finalize())
        })
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => {
                let now = duration.as_secs() as usize;
                now > self.exp
            }
            Err(_) => {
                // If we can't get current time, assume token is expired for security
                true
            }
        }
    }
}

/// Manages JWT token operations
pub struct TokenManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
    revocation_store: Option<SharedTokenRevocationStore>,
}

impl TokenManager {
    /// Creates a new token manager with a secret
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            validation: Validation::default(),
            revocation_store: None,
        }
    }
    
    /// Creates a new token manager with revocation support
    pub fn with_revocation_store(secret: &str, revocation_store: SharedTokenRevocationStore) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            validation: Validation::default(),
            revocation_store: Some(revocation_store),
        }
    }

    /// Generates a JWT token for the given claims
    pub fn generate_token(&self, claims: &Claims) -> Result<String> {
        encode(&Header::default(), claims, &self.encoding_key)
            .map_err(|e| RustySocksError::AuthError(format!("Failed to generate token: {}", e)))
    }

    /// Validates and decodes a JWT token (includes revocation checking)
    pub async fn validate_token(&self, token: &str) -> Result<TokenData<Claims>> {
        // Start timing protection
        let timer = AuthTimer::default();
        
        // First validate the token signature and structure
        let token_data = match decode::<Claims>(token, &self.decoding_key, &self.validation) {
            Ok(data) => data,
            Err(e) => {
                timer.wait().await;
                log_security_event(SecurityEvent::TokenValidationFailed {
                    token_id: None,
                    ip: None,
                    reason: format!("Invalid token signature: {}", e),
                }).await;
                return Err(RustySocksError::AuthError(format!("Invalid token: {}", e)));
            }
        };
        
        // Check if token is revoked (if revocation store is available)
        if let Some(revocation_store) = &self.revocation_store {
            let token_id = token_data.claims.get_token_id();
            if revocation_store.is_token_revoked(&token_id).await.unwrap_or(false) {
                timer.wait().await;
                log_security_event(SecurityEvent::TokenValidationFailed {
                    token_id: Some(token_id),
                    ip: None,
                    reason: "Token has been revoked".to_string(),
                }).await;
                return Err(RustySocksError::AuthError("Token has been revoked".to_string()));
            }
        }
        
        // Ensure minimum time has elapsed before returning success
        timer.wait().await;
        Ok(token_data)
    }
    
    /// Validates and decodes a JWT token (synchronous version for compatibility)
    pub fn validate_token_sync(&self, token: &str) -> Result<TokenData<Claims>> {
        decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| RustySocksError::AuthError(format!("Invalid token: {}", e)))
    }

    /// Extracts claims from a token string (includes revocation checking)
    pub async fn get_claims(&self, token: &str) -> Result<Claims> {
        let token_data = self.validate_token(token).await?;
        Ok(token_data.claims)
    }
    
    /// Extracts claims from a token string (synchronous version)
    pub fn get_claims_sync(&self, token: &str) -> Result<Claims> {
        let token_data = self.validate_token_sync(token)?;
        Ok(token_data.claims)
    }

    /// Validates a token and returns the user ID if valid (includes revocation checking)
    pub async fn validate_and_get_user_id(&self, token: &str) -> Result<String> {
        let timer = AuthTimer::default();
        
        let claims = match self.get_claims(token).await {
            Ok(claims) => claims,
            Err(e) => {
                timer.wait().await;
                return Err(e);
            }
        };

        if claims.is_expired() {
            timer.wait().await;
            log_security_event(SecurityEvent::TokenValidationFailed {
                token_id: Some(claims.get_token_id()),
                ip: None,
                reason: "Token expired".to_string(),
            }).await;
            return Err(RustySocksError::AuthError("Token expired".to_string()));
        }

        timer.wait().await;
        Ok(claims.sub)
    }
    
    /// Validates a token and returns the user ID if valid (synchronous version)
    pub fn validate_and_get_user_id_sync(&self, token: &str) -> Result<String> {
        let claims = self.get_claims_sync(token)?;

        if claims.is_expired() {
            return Err(RustySocksError::AuthError("Token expired".to_string()));
        }

        Ok(claims.sub)
    }
    
    /// Revoke a specific token
    pub async fn revoke_token(&self, token: &str, reason: RevocationReason) -> Result<()> {
        if let Some(revocation_store) = &self.revocation_store {
            // First validate the token to extract claims
            let claims = self.get_claims_sync(token)?; // Use sync version to avoid circular async
            
            let revoked_token = RevokedToken {
                token_id: claims.get_token_id(),
                user_id: claims.sub.clone(),
                revoked_at: chrono::Utc::now(),
                expires_at: chrono::DateTime::from_timestamp(claims.exp as i64, 0)
                    .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::hours(24)),
                reason,
                context: None,
            };
            
            revocation_store.revoke_token(revoked_token).await?;
            log::info!("Token revoked for user: {}", claims.sub);
            Ok(())
        } else {
            Err(RustySocksError::SystemError("Token revocation not enabled".to_string()))
        }
    }
    
    /// Revoke all tokens for a user
    pub async fn revoke_user_tokens(&self, user_id: &str, reason: RevocationReason) -> Result<usize> {
        if let Some(revocation_store) = &self.revocation_store {
            revocation_store.revoke_user_tokens(user_id, reason).await
        } else {
            Err(RustySocksError::SystemError("Token revocation not enabled".to_string()))
        }
    }
    
    /// Get revocation statistics
    pub async fn get_revocation_stats(&self) -> Result<crate::storage::token_revocation::RevocationStats> {
        if let Some(revocation_store) = &self.revocation_store {
            revocation_store.get_revocation_stats().await
        } else {
            Err(RustySocksError::SystemError("Token revocation not enabled".to_string()))
        }
    }
    
    /// Check if revocation is enabled
    pub fn has_revocation_support(&self) -> bool {
        self.revocation_store.is_some()
    }
}

/// Generate a secure token hash for identification purposes
pub fn generate_token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Extracts bearer token from Authorization header
pub fn extract_bearer_token(auth_header: &str) -> Option<String> {
    if auth_header.starts_with("Bearer ") {
        Some(auth_header[7..].to_string())
    } else {
        None
    }
}

