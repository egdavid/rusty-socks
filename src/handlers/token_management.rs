//! Token management API endpoints
//!
//! This module provides HTTP API endpoints for token management operations
//! including token revocation, user token management, and admin functions.

use serde::{Deserialize, Serialize};
use warp::{Filter, Reply};

use crate::auth::token::TokenManager;
use crate::core::server::SharedServerManager;
use crate::error::{Result, RustySocksError};
use crate::storage::token_revocation::{RevocationReason, RevocationStats};

/// Request to revoke a specific token
#[derive(Debug, Deserialize)]
pub struct RevokeTokenRequest {
    /// The token to revoke
    pub token: String,
    /// Reason for revocation
    pub reason: Option<String>,
}

/// Request to revoke all tokens for a user
#[derive(Debug, Deserialize)]
pub struct RevokeUserTokensRequest {
    /// User ID whose tokens should be revoked
    pub user_id: String,
    /// Reason for revocation
    pub reason: RevocationReason,
    /// Optional context/description
    pub context: Option<String>,
}

/// Response for token revocation operations
#[derive(Debug, Serialize)]
pub struct TokenRevocationResponse {
    /// Whether the operation was successful
    pub success: bool,
    /// Descriptive message
    pub message: String,
    /// Number of tokens affected (for bulk operations)
    pub tokens_affected: Option<usize>,
}

/// Response for revocation statistics
#[derive(Debug, Serialize)]
pub struct RevocationStatsResponse {
    /// Revocation statistics
    pub stats: RevocationStats,
    /// Timestamp when stats were generated
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// Token management API handlers
pub struct TokenManagementHandler {
    token_manager: std::sync::Arc<TokenManager>,
    server_manager: SharedServerManager,
}

impl TokenManagementHandler {
    /// Create a new token management handler
    pub fn new(token_manager: std::sync::Arc<TokenManager>, server_manager: SharedServerManager) -> Self {
        Self {
            token_manager,
            server_manager,
        }
    }

    /// Handle token revocation request
    pub async fn handle_revoke_token(
        &self,
        request: RevokeTokenRequest,
        requesting_user_id: String,
    ) -> Result<TokenRevocationResponse> {
        // Verify that the requesting user has permission to revoke tokens
        if !self.can_user_revoke_tokens(&requesting_user_id).await? {
            return Err(RustySocksError::PermissionDenied(
                "User lacks token revocation permissions".to_string()
            ));
        }

        // Determine revocation reason
        let reason = if request.reason.as_deref() == Some("security_incident") {
            RevocationReason::SecurityIncident
        } else if request.reason.as_deref() == Some("admin_action") {
            RevocationReason::AdminRevocation
        } else {
            RevocationReason::AdminRevocation // Default for admin-initiated revocations
        };

        // Revoke the token
        match self.token_manager.revoke_token(&request.token, reason).await {
            Ok(_) => Ok(TokenRevocationResponse {
                success: true,
                message: "Token revoked successfully".to_string(),
                tokens_affected: Some(1),
            }),
            Err(e) => Ok(TokenRevocationResponse {
                success: false,
                message: format!("Failed to revoke token: {}", e),
                tokens_affected: Some(0),
            }),
        }
    }

    /// Handle bulk user token revocation
    pub async fn handle_revoke_user_tokens(
        &self,
        request: RevokeUserTokensRequest,
        requesting_user_id: String,
    ) -> Result<TokenRevocationResponse> {
        // Verify that the requesting user has permission to revoke user tokens
        if !self.can_user_revoke_user_tokens(&requesting_user_id, &request.user_id).await? {
            return Err(RustySocksError::PermissionDenied(
                "User lacks permission to revoke tokens for this user".to_string()
            ));
        }

        // Revoke all tokens for the user
        match self.token_manager.revoke_user_tokens(&request.user_id, request.reason).await {
            Ok(count) => Ok(TokenRevocationResponse {
                success: true,
                message: format!("Revoked {} tokens for user {}", count, request.user_id),
                tokens_affected: Some(count),
            }),
            Err(e) => Ok(TokenRevocationResponse {
                success: false,
                message: format!("Failed to revoke user tokens: {}", e),
                tokens_affected: Some(0),
            }),
        }
    }

    /// Handle request for revocation statistics
    pub async fn handle_get_revocation_stats(
        &self,
        requesting_user_id: String,
    ) -> Result<RevocationStatsResponse> {
        // Verify that the requesting user has permission to view stats
        if !self.can_user_view_revocation_stats(&requesting_user_id).await? {
            return Err(RustySocksError::PermissionDenied(
                "User lacks permission to view revocation statistics".to_string()
            ));
        }

        // Get revocation statistics
        let stats = self.token_manager.get_revocation_stats().await?;

        Ok(RevocationStatsResponse {
            stats,
            generated_at: chrono::Utc::now(),
        })
    }

    /// Handle user logout (revoke current session token)
    pub async fn handle_logout(
        &self,
        token: String,
        _user_id: String,
    ) -> Result<TokenRevocationResponse> {
        // Users can always logout (revoke their own current token)
        match self.token_manager.revoke_token(&token, RevocationReason::UserLogout).await {
            Ok(_) => Ok(TokenRevocationResponse {
                success: true,
                message: "Logged out successfully".to_string(),
                tokens_affected: Some(1),
            }),
            Err(e) => Ok(TokenRevocationResponse {
                success: false,
                message: format!("Failed to logout: {}", e),
                tokens_affected: Some(0),
            }),
        }
    }

    /// Check if user can revoke arbitrary tokens
    async fn can_user_revoke_tokens(&self, user_id: &str) -> Result<bool> {
        // Only admins and owners can revoke arbitrary tokens
        let user_info = self.server_manager.get_user_info(user_id).await;
        if let Some(info) = user_info {
            Ok(info.contains("Admin") || info.contains("Owner"))
        } else {
            Ok(false)
        }
    }

    /// Check if user can revoke tokens for a specific user
    async fn can_user_revoke_user_tokens(&self, requesting_user_id: &str, target_user_id: &str) -> Result<bool> {
        // Users can always revoke their own tokens
        if requesting_user_id == target_user_id {
            return Ok(true);
        }

        // Admins and owners can revoke other users' tokens
        self.can_user_revoke_tokens(requesting_user_id).await
    }

    /// Check if user can view revocation statistics
    async fn can_user_view_revocation_stats(&self, user_id: &str) -> Result<bool> {
        // Moderators and above can view statistics
        let user_info = self.server_manager.get_user_info(user_id).await;
        if let Some(info) = user_info {
            Ok(info.contains("Admin") || info.contains("Owner") || info.contains("Moderator"))
        } else {
            Ok(false)
        }
    }
}

/// Create token management API routes (temporarily simplified)
pub fn create_token_management_routes(
    _token_manager: std::sync::Arc<TokenManager>,
    _server_manager: SharedServerManager,
) -> impl Filter<Extract = impl Reply, Error = warp::Rejection> + Clone {
    // TODO: Implement full token management API routes
    // For now, return a simple placeholder route to avoid compilation issues
    warp::path!("api" / "tokens" / "health")
        .and(warp::get())
        .map(|| {
            warp::reply::json(&serde_json::json!({
                "status": "ok",
                "message": "Token revocation system is active"
            }))
        })
}

// TODO: Implement full API routes once basic functionality is working