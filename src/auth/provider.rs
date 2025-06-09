//! Modular authentication provider system
//! 
//! This module provides a trait-based system for pluggable authentication
//! backends, allowing users to choose between JWT, API keys, or custom auth.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::auth::user::{UserRole, Permission};
use crate::error::{Result, RustySocksError};

/// User information returned by authentication providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub username: String,
    pub email: Option<String>,
    pub roles: HashMap<String, UserRole>, // room_id -> role
    pub global_permissions: Vec<Permission>,
    pub metadata: HashMap<String, String>,
}

/// Authentication result
#[derive(Debug)]
pub enum AuthResult {
    Success(AuthenticatedUser),
    Failed(String),
    Expired,
    Invalid,
}

/// Trait for authentication providers
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Authenticate a token/credential and return user info
    async fn authenticate(&self, token: &str) -> Result<AuthResult>;
    
    /// Validate if a token is still valid (for refresh checks)
    async fn validate_token(&self, token: &str) -> Result<bool>;
    
    /// Get the provider name for logging/debugging
    fn provider_name(&self) -> &'static str;
    
    /// Optional: Generate a new token for a user (for refresh tokens)
    async fn generate_token(&self, _user_id: &str) -> Result<String> {
        Err(RustySocksError::NotImplemented(
            format!("{} provider does not support token generation", self.provider_name())
        ))
    }
    
    /// Optional: Revoke/invalidate a token
    async fn revoke_token(&self, _token: &str) -> Result<()> {
        Err(RustySocksError::NotImplemented(
            format!("{} provider does not support token revocation", self.provider_name())
        ))
    }
}

/// JWT-based authentication provider
pub struct JwtAuthProvider {
    secret: String,
    issuer: Option<String>,
    audience: Option<String>,
}

impl JwtAuthProvider {
    pub fn new(secret: String) -> Self {
        Self {
            secret,
            issuer: None,
            audience: None,
        }
    }
    
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }
    
    pub fn with_audience(mut self, audience: String) -> Self {
        self.audience = Some(audience);
        self
    }
}

#[async_trait]
impl AuthProvider for JwtAuthProvider {
    async fn authenticate(&self, token: &str) -> Result<AuthResult> {
        use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
        
        let mut validation = Validation::new(Algorithm::HS256);
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(ref aud) = self.audience {
            validation.set_audience(&[aud]);
        }
        
        match decode::<crate::auth::token::Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &validation,
        ) {
            Ok(token_data) => {
                let claims = token_data.claims;
                
                // Check if token is expired
                let now = chrono::Utc::now().timestamp() as usize;
                if claims.exp < now {
                    return Ok(AuthResult::Expired);
                }
                
                // Convert claims to AuthenticatedUser
                let user = AuthenticatedUser {
                    user_id: claims.sub,
                    username: claims.username.unwrap_or_else(|| "Unknown".to_string()),
                    email: claims.email,
                    roles: HashMap::new(), // TODO: Extract from JWT claims
                    global_permissions: vec![Permission::SendMessages], // TODO: Extract from JWT
                    metadata: HashMap::new(),
                };
                
                Ok(AuthResult::Success(user))
            }
            Err(e) => {
                log::debug!("JWT validation failed: {}", e);
                Ok(AuthResult::Invalid)
            }
        }
    }
    
    async fn validate_token(&self, token: &str) -> Result<bool> {
        match self.authenticate(token).await? {
            AuthResult::Success(_) => Ok(true),
            _ => Ok(false),
        }
    }
    
    fn provider_name(&self) -> &'static str {
        "JWT"
    }
    
    async fn generate_token(&self, user_id: &str) -> Result<String> {
        use jsonwebtoken::{encode, EncodingKey, Header};
        
        let mut claims = crate::auth::token::Claims::new(
            user_id.to_string(),
            user_id.to_string(), // Could be looked up from database
            None,
        ).map_err(|e| RustySocksError::AuthenticationError(format!("Failed to create claims: {}", e)))?;
        
        // Set optional fields
        claims.iss = self.issuer.clone();
        claims.aud = self.audience.clone();
        
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        ).map_err(|e| RustySocksError::AuthenticationError(format!("Token generation failed: {}", e)))
    }
}

/// API Key-based authentication provider
pub struct ApiKeyAuthProvider {
    /// Map of API key -> user info
    api_keys: HashMap<String, AuthenticatedUser>,
}

impl ApiKeyAuthProvider {
    pub fn new() -> Self {
        Self {
            api_keys: HashMap::new(),
        }
    }
    
    /// Add an API key for a user
    pub fn add_api_key(&mut self, api_key: String, user: AuthenticatedUser) {
        self.api_keys.insert(api_key, user);
    }
    
    /// Remove an API key
    pub fn remove_api_key(&mut self, api_key: &str) {
        self.api_keys.remove(api_key);
    }
    
    /// Load API keys from a configuration source
    pub fn load_from_config(&mut self, _config_path: &str) -> Result<()> {
        // Configuration loading implementation would be added here
        
        // Add a demo API key for development
        let demo_user = AuthenticatedUser {
            user_id: "api_user_1".to_string(),
            username: "API User".to_string(),
            email: Some("api@example.com".to_string()),
            roles: HashMap::new(),
            global_permissions: vec![Permission::SendMessages, Permission::CreateRooms],
            metadata: HashMap::new(),
        };
        
        self.add_api_key("demo-api-key-12345".to_string(), demo_user);
        
        Ok(())
    }
}

#[async_trait]
impl AuthProvider for ApiKeyAuthProvider {
    async fn authenticate(&self, token: &str) -> Result<AuthResult> {
        match self.api_keys.get(token) {
            Some(user) => Ok(AuthResult::Success(user.clone())),
            None => Ok(AuthResult::Invalid),
        }
    }
    
    async fn validate_token(&self, token: &str) -> Result<bool> {
        Ok(self.api_keys.contains_key(token))
    }
    
    fn provider_name(&self) -> &'static str {
        "API_KEY"
    }
    
    async fn revoke_token(&self, _token: &str) -> Result<()> {
        // Note: This would need &mut self
        // There is no return implemented
        Err(RustySocksError::NotImplemented(
            "API key revocation requires mutable access".to_string()
        ))
    }
}

/// No-auth provider for development/testing
pub struct NoAuthProvider {
    default_user: AuthenticatedUser,
}

impl NoAuthProvider {
    pub fn new() -> Self {
        let default_user = AuthenticatedUser {
            user_id: "anonymous".to_string(),
            username: "Anonymous".to_string(),
            email: None,
            roles: HashMap::new(),
            global_permissions: vec![Permission::SendMessages],
            metadata: HashMap::new(),
        };
        
        Self { default_user }
    }
}

#[async_trait]
impl AuthProvider for NoAuthProvider {
    async fn authenticate(&self, _token: &str) -> Result<AuthResult> {
        Ok(AuthResult::Success(self.default_user.clone()))
    }
    
    async fn validate_token(&self, _token: &str) -> Result<bool> {
        Ok(true)
    }
    
    fn provider_name(&self) -> &'static str {
        "NO_AUTH"
    }
}

/// Multi-provider authentication manager
pub struct AuthManager {
    providers: Vec<Box<dyn AuthProvider>>,
    fallback_to_anonymous: bool,
}

impl AuthManager {
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            fallback_to_anonymous: false,
        }
    }
    
    /// Add an authentication provider
    pub fn add_provider(mut self, provider: Box<dyn AuthProvider>) -> Self {
        self.providers.push(provider);
        self
    }
    
    /// Enable fallback to anonymous access if all providers fail
    pub fn with_anonymous_fallback(mut self) -> Self {
        self.fallback_to_anonymous = true;
        self
    }
    
    /// Try to authenticate with all providers in order
    pub async fn authenticate(&self, token: &str) -> Result<AuthResult> {
        for provider in &self.providers {
            match provider.authenticate(token).await? {
                AuthResult::Success(user) => {
                    log::debug!("Authentication successful with provider: {}", provider.provider_name());
                    return Ok(AuthResult::Success(user));
                }
                AuthResult::Failed(reason) => {
                    log::debug!("Authentication failed with provider {}: {}", provider.provider_name(), reason);
                    continue;
                }
                AuthResult::Expired => {
                    log::debug!("Token expired with provider: {}", provider.provider_name());
                    continue;
                }
                AuthResult::Invalid => {
                    log::debug!("Invalid token with provider: {}", provider.provider_name());
                    continue;
                }
            }
        }
        
        // If all providers failed and anonymous fallback is enabled
        if self.fallback_to_anonymous {
            let anonymous_user = AuthenticatedUser {
                user_id: format!("anon_{}", uuid::Uuid::new_v4()),
                username: "Anonymous".to_string(),
                email: None,
                roles: HashMap::new(),
                global_permissions: vec![Permission::SendMessages],
                metadata: HashMap::new(),
            };
            return Ok(AuthResult::Success(anonymous_user));
        }
        
        Ok(AuthResult::Failed("No authentication provider accepted the token".to_string()))
    }
    
    /// Validate token with any provider
    pub async fn validate_token(&self, token: &str) -> Result<bool> {
        for provider in &self.providers {
            if provider.validate_token(token).await? {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

/// Builder for creating auth managers with common configurations
pub struct AuthManagerBuilder;

impl AuthManagerBuilder {
    /// Create a JWT-only auth manager
    pub fn jwt_only(secret: String) -> AuthManager {
        AuthManager::new()
            .add_provider(Box::new(JwtAuthProvider::new(secret)))
    }
    
    /// Create an API key-only auth manager
    pub fn api_key_only() -> AuthManager {
        let mut provider = ApiKeyAuthProvider::new();
        provider.load_from_config("").unwrap(); // Load demo keys
        
        AuthManager::new()
            .add_provider(Box::new(provider))
    }
    
    /// Create a multi-provider auth manager (JWT + API keys)
    pub fn multi_provider(jwt_secret: String) -> AuthManager {
        let mut api_provider = ApiKeyAuthProvider::new();
        api_provider.load_from_config("").unwrap();
        
        AuthManager::new()
            .add_provider(Box::new(JwtAuthProvider::new(jwt_secret)))
            .add_provider(Box::new(api_provider))
    }
    
    /// Create a development auth manager (no auth required)
    pub fn development() -> AuthManager {
        AuthManager::new()
            .add_provider(Box::new(NoAuthProvider::new()))
    }
    
    /// Create a permissive auth manager (tries JWT, falls back to anonymous)
    pub fn permissive(jwt_secret: String) -> AuthManager {
        AuthManager::new()
            .add_provider(Box::new(JwtAuthProvider::new(jwt_secret)))
            .with_anonymous_fallback()
    }
}