//! Token revocation storage and management
//! 
//! This module provides infrastructure for managing revoked JWT tokens
//! to enable secure token invalidation and logout functionality.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::Result;

/// Information about a revoked token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedToken {
    /// JWT ID (jti) or token hash for identification
    pub token_id: String,
    /// User ID who owned the token
    pub user_id: String,
    /// When the token was revoked
    pub revoked_at: DateTime<Utc>,
    /// When the original token expires (for cleanup)
    pub expires_at: DateTime<Utc>,
    /// Reason for revocation (logout, security, admin action, etc.)
    pub reason: RevocationReason,
    /// Optional additional context
    pub context: Option<String>,
}

/// Reason for token revocation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    /// User initiated logout
    UserLogout,
    /// User changed password/credentials
    CredentialChange,
    /// Security incident detected
    SecurityIncident,
    /// Administrative action
    AdminRevocation,
    /// Account suspended/banned
    AccountSuspension,
    /// Token expired (automatic cleanup)
    Expired,
}

/// Token revocation storage trait
#[async_trait]
pub trait TokenRevocationStore: Send + Sync {
    /// Add a token to the revocation list
    async fn revoke_token(&self, revoked_token: RevokedToken) -> Result<()>;
    
    /// Check if a token is revoked
    async fn is_token_revoked(&self, token_id: &str) -> Result<bool>;
    
    /// Get revocation information for a token
    async fn get_revocation_info(&self, token_id: &str) -> Result<Option<RevokedToken>>;
    
    /// Revoke all tokens for a specific user
    async fn revoke_user_tokens(&self, user_id: &str, reason: RevocationReason) -> Result<usize>;
    
    /// Clean up expired token revocations
    async fn cleanup_expired_revocations(&self) -> Result<usize>;
    
    /// Get all revoked tokens for a user (for admin purposes)
    async fn get_user_revoked_tokens(&self, user_id: &str) -> Result<Vec<RevokedToken>>;
    
    /// Get revocation statistics
    async fn get_revocation_stats(&self) -> Result<RevocationStats>;
}

/// Statistics about token revocations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationStats {
    /// Total number of revoked tokens
    pub total_revoked: usize,
    /// Number of revocations by reason
    pub by_reason: HashMap<RevocationReason, usize>,
    /// Number of revocations in the last 24 hours
    pub recent_revocations: usize,
    /// Number of active (non-expired) revocations
    pub active_revocations: usize,
}

/// In-memory implementation of token revocation store
pub struct MemoryTokenRevocationStore {
    /// Map of token_id -> RevokedToken
    revoked_tokens: Arc<RwLock<HashMap<String, RevokedToken>>>,
    /// Index by user_id for efficient user-based operations
    user_tokens: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl MemoryTokenRevocationStore {
    /// Create a new memory-based token revocation store
    pub fn new() -> Self {
        Self {
            revoked_tokens: Arc::new(RwLock::new(HashMap::new())),
            user_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Start background cleanup task
    pub fn start_cleanup_task(self: Arc<Self>) {
        let store = Arc::clone(&self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Every hour
            loop {
                interval.tick().await;
                if let Err(e) = store.cleanup_expired_revocations().await {
                    log::error!("Failed to cleanup expired token revocations: {}", e);
                }
            }
        });
    }
}

#[async_trait]
impl TokenRevocationStore for MemoryTokenRevocationStore {
    async fn revoke_token(&self, revoked_token: RevokedToken) -> Result<()> {
        let token_id = revoked_token.token_id.clone();
        let user_id = revoked_token.user_id.clone();
        let log_token_id = token_id.clone(); // Clone for logging
        
        // Add to revoked tokens
        {
            let mut revoked_tokens = self.revoked_tokens.write().await;
            revoked_tokens.insert(token_id.clone(), revoked_token);
        }
        
        // Update user index
        {
            let mut user_tokens = self.user_tokens.write().await;
            user_tokens
                .entry(user_id)
                .or_insert_with(Vec::new)
                .push(token_id);
        }
        
        log::info!("Token revoked: {}", log_token_id);
        Ok(())
    }
    
    async fn is_token_revoked(&self, token_id: &str) -> Result<bool> {
        let revoked_tokens = self.revoked_tokens.read().await;
        Ok(revoked_tokens.contains_key(token_id))
    }
    
    async fn get_revocation_info(&self, token_id: &str) -> Result<Option<RevokedToken>> {
        let revoked_tokens = self.revoked_tokens.read().await;
        Ok(revoked_tokens.get(token_id).cloned())
    }
    
    async fn revoke_user_tokens(&self, user_id: &str, reason: RevocationReason) -> Result<usize> {
        let mut count = 0;
        let now = Utc::now();
        
        // Get all tokens for this user
        let token_ids = {
            let user_tokens = self.user_tokens.read().await;
            user_tokens.get(user_id).cloned().unwrap_or_default()
        };
        
        // Mark all user tokens as revoked
        {
            let mut revoked_tokens = self.revoked_tokens.write().await;
            for token_id in token_ids {
                if !revoked_tokens.contains_key(&token_id) {
                    let revoked_token = RevokedToken {
                        token_id: token_id.clone(),
                        user_id: user_id.to_string(),
                        revoked_at: now,
                        expires_at: now + chrono::Duration::hours(24), // Default expiration
                        reason: reason.clone(),
                        context: Some(format!("Bulk revocation for user {}", user_id)),
                    };
                    revoked_tokens.insert(token_id, revoked_token);
                    count += 1;
                }
            }
        }
        
        log::info!("Revoked {} tokens for user {} (reason: {:?})", count, user_id, reason);
        Ok(count)
    }
    
    async fn cleanup_expired_revocations(&self) -> Result<usize> {
        let now = Utc::now();
        let mut removed_count = 0;
        let mut tokens_to_remove = Vec::new();
        
        // Find expired revocations
        {
            let revoked_tokens = self.revoked_tokens.read().await;
            for (token_id, revoked_token) in revoked_tokens.iter() {
                if revoked_token.expires_at < now {
                    tokens_to_remove.push((token_id.clone(), revoked_token.user_id.clone()));
                }
            }
        }
        
        // Remove expired revocations
        if !tokens_to_remove.is_empty() {
            let mut revoked_tokens = self.revoked_tokens.write().await;
            let mut user_tokens = self.user_tokens.write().await;
            
            for (token_id, user_id) in tokens_to_remove {
                revoked_tokens.remove(&token_id);
                
                // Remove from user index
                if let Some(user_token_list) = user_tokens.get_mut(&user_id) {
                    user_token_list.retain(|id| id != &token_id);
                    if user_token_list.is_empty() {
                        user_tokens.remove(&user_id);
                    }
                }
                
                removed_count += 1;
            }
        }
        
        if removed_count > 0 {
            log::info!("Cleaned up {} expired token revocations", removed_count);
        }
        
        Ok(removed_count)
    }
    
    async fn get_user_revoked_tokens(&self, user_id: &str) -> Result<Vec<RevokedToken>> {
        let revoked_tokens = self.revoked_tokens.read().await;
        let user_tokens = self.user_tokens.read().await;
        
        let mut result = Vec::new();
        if let Some(token_ids) = user_tokens.get(user_id) {
            for token_id in token_ids {
                if let Some(revoked_token) = revoked_tokens.get(token_id) {
                    result.push(revoked_token.clone());
                }
            }
        }
        
        Ok(result)
    }
    
    async fn get_revocation_stats(&self) -> Result<RevocationStats> {
        let revoked_tokens = self.revoked_tokens.read().await;
        let now = Utc::now();
        let twenty_four_hours_ago = now - chrono::Duration::hours(24);
        
        let mut by_reason = HashMap::new();
        let mut recent_revocations = 0;
        let mut active_revocations = 0;
        
        for revoked_token in revoked_tokens.values() {
            // Count by reason
            *by_reason.entry(revoked_token.reason.clone()).or_insert(0) += 1;
            
            // Count recent revocations
            if revoked_token.revoked_at > twenty_four_hours_ago {
                recent_revocations += 1;
            }
            
            // Count active (non-expired) revocations
            if revoked_token.expires_at > now {
                active_revocations += 1;
            }
        }
        
        Ok(RevocationStats {
            total_revoked: revoked_tokens.len(),
            by_reason,
            recent_revocations,
            active_revocations,
        })
    }
}

impl Default for MemoryTokenRevocationStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared reference to token revocation store
pub type SharedTokenRevocationStore = Arc<dyn TokenRevocationStore>;

/// Create a new memory-based token revocation store
pub fn create_memory_revocation_store() -> SharedTokenRevocationStore {
    Arc::new(MemoryTokenRevocationStore::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[tokio::test]
    async fn test_token_revocation() {
        let store = MemoryTokenRevocationStore::new();
        
        let revoked_token = RevokedToken {
            token_id: "test_token_123".to_string(),
            user_id: "user_456".to_string(),
            revoked_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            reason: RevocationReason::UserLogout,
            context: Some("Test revocation".to_string()),
        };
        
        // Test revocation
        store.revoke_token(revoked_token.clone()).await.unwrap();
        
        // Test checking if token is revoked
        assert!(store.is_token_revoked("test_token_123").await.unwrap());
        assert!(!store.is_token_revoked("non_existent_token").await.unwrap());
        
        // Test getting revocation info
        let info = store.get_revocation_info("test_token_123").await.unwrap();
        assert!(info.is_some());
        assert_eq!(info.unwrap().reason, RevocationReason::UserLogout);
    }
    
    #[tokio::test]
    async fn test_user_token_revocation() {
        let store = MemoryTokenRevocationStore::new();
        
        // Add tokens for a user
        let token1 = RevokedToken {
            token_id: "token1".to_string(),
            user_id: "user1".to_string(),
            revoked_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            reason: RevocationReason::UserLogout,
            context: None,
        };
        
        store.revoke_token(token1).await.unwrap();
        
        // Revoke all tokens for user
        let count = store.revoke_user_tokens("user1", RevocationReason::SecurityIncident).await.unwrap();
        assert_eq!(count, 0); // Token was already revoked
        
        // Check user's revoked tokens
        let user_tokens = store.get_user_revoked_tokens("user1").await.unwrap();
        assert_eq!(user_tokens.len(), 1);
    }
    
    #[tokio::test]
    async fn test_cleanup_expired_revocations() {
        let store = MemoryTokenRevocationStore::new();
        
        // Add an expired token
        let expired_token = RevokedToken {
            token_id: "expired_token".to_string(),
            user_id: "user1".to_string(),
            revoked_at: Utc::now() - Duration::hours(25),
            expires_at: Utc::now() - Duration::hours(1), // Expired
            reason: RevocationReason::UserLogout,
            context: None,
        };
        
        store.revoke_token(expired_token).await.unwrap();
        
        // Cleanup expired revocations
        let cleaned = store.cleanup_expired_revocations().await.unwrap();
        assert_eq!(cleaned, 1);
        
        // Token should no longer be considered revoked
        assert!(!store.is_token_revoked("expired_token").await.unwrap());
    }
    
    #[tokio::test]
    async fn test_revocation_stats() {
        let store = MemoryTokenRevocationStore::new();
        
        // Add tokens with different reasons
        let token1 = RevokedToken {
            token_id: "token1".to_string(),
            user_id: "user1".to_string(),
            revoked_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            reason: RevocationReason::UserLogout,
            context: None,
        };
        
        let token2 = RevokedToken {
            token_id: "token2".to_string(),
            user_id: "user2".to_string(),
            revoked_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            reason: RevocationReason::SecurityIncident,
            context: None,
        };
        
        store.revoke_token(token1).await.unwrap();
        store.revoke_token(token2).await.unwrap();
        
        // Get stats
        let stats = store.get_revocation_stats().await.unwrap();
        assert_eq!(stats.total_revoked, 2);
        assert_eq!(stats.by_reason.get(&RevocationReason::UserLogout), Some(&1));
        assert_eq!(stats.by_reason.get(&RevocationReason::SecurityIncident), Some(&1));
        assert_eq!(stats.recent_revocations, 2);
        assert_eq!(stats.active_revocations, 2);
    }
}