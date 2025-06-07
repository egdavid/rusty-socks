use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Result, RustySocksError};

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Username
    pub username: String,
    /// Expiration time (as UTC timestamp)
    pub exp: usize,
    /// Issued at (as UTC timestamp)
    pub iat: usize,
    /// Not before (as UTC timestamp)
    pub nbf: usize,
    /// Optional email
    pub email: Option<String>,
}

impl Claims {
    /// Creates new claims for a user
    pub fn new(user_id: String, username: String, email: Option<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as usize;

        Self {
            sub: user_id,
            username,
            exp: now + 86400, // 24 hours from now
            iat: now,
            nbf: now,
            email,
        }
    }

    /// Creates claims with custom expiration
    pub fn with_expiration(
        user_id: String,
        username: String,
        email: Option<String>,
        hours: usize,
    ) -> Self {
        let mut claims = Self::new(user_id, username, email);
        let now = claims.iat;
        claims.exp = now + (hours * 3600);
        claims
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as usize;
        
        now > self.exp
    }
}

/// Manages JWT token operations
pub struct TokenManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl TokenManager {
    /// Creates a new token manager with a secret
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            validation: Validation::default(),
        }
    }

    /// Generates a JWT token for the given claims
    pub fn generate_token(&self, claims: &Claims) -> Result<String> {
        encode(&Header::default(), claims, &self.encoding_key)
            .map_err(|e| RustySocksError::AuthError(format!("Failed to generate token: {}", e)))
    }

    /// Validates and decodes a JWT token
    pub fn validate_token(&self, token: &str) -> Result<TokenData<Claims>> {
        decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| RustySocksError::AuthError(format!("Invalid token: {}", e)))
    }

    /// Extracts claims from a token string
    pub fn get_claims(&self, token: &str) -> Result<Claims> {
        let token_data = self.validate_token(token)?;
        Ok(token_data.claims)
    }

    /// Validates a token and returns the user ID if valid
    pub fn validate_and_get_user_id(&self, token: &str) -> Result<String> {
        let claims = self.get_claims(token)?;
        
        if claims.is_expired() {
            return Err(RustySocksError::AuthError("Token expired".to_string()));
        }
        
        Ok(claims.sub)
    }
}

/// Extracts bearer token from Authorization header
pub fn extract_bearer_token(auth_header: &str) -> Option<String> {
    if auth_header.starts_with("Bearer ") {
        Some(auth_header[7..].to_string())
    } else {
        None
    }
}

// TODO: Implement refresh tokens for long-lived sessions
// TODO: Add token revocation mechanism
// TODO: Support multiple signing algorithms (RS256, ES256)