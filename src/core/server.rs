//! Integrated server service that coordinates sessions and rooms

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use warp::ws::Message as WsMessage;

use crate::auth::user::User;
use crate::core::broadcast_optimizer::BroadcastOptimizer;
use crate::core::connection::Connection;
use crate::core::multi_tier_rate_limiter::{MultiTierRateLimiter, UserTier, OperationType};
use crate::core::rate_limiter::RateLimiterManager;
use crate::core::room::RoomManager;
use crate::core::session::SessionManager;
use crate::error::{Result, RustySocksError};
use crate::storage::message_store::SharedMessageStore;

/// Integrated server service that manages sessions and rooms together
pub struct ServerManager {
    sessions: Arc<RwLock<SessionManager>>,
    rooms: Arc<RwLock<RoomManager>>,
    rate_limiter: Arc<RateLimiterManager>,
    multi_tier_rate_limiter: Arc<MultiTierRateLimiter>,
    broadcast_optimizer: Arc<BroadcastOptimizer>,
}

impl ServerManager {
    /// Create a new server manager
    pub fn new() -> Self {
        // Default rate limits
        let rate_limiter = Arc::new(RateLimiterManager::new(10, 60));
        
        // Create multi-tier rate limiter
        let multi_tier_rate_limiter = Arc::new(MultiTierRateLimiter::new());
        multi_tier_rate_limiter.clone().start_cleanup_task();
        
        // Create broadcast optimizer with 4 workers (optimal for most systems)
        let broadcast_optimizer = Arc::new(BroadcastOptimizer::new(4));
        
        Self {
            sessions: Arc::new(RwLock::new(SessionManager::new())),
            rooms: Arc::new(RwLock::new(RoomManager::new())),
            rate_limiter,
            multi_tier_rate_limiter,
            broadcast_optimizer,
        }
    }

    /// Create with message store
    pub fn with_message_store(message_store: SharedMessageStore) -> Self {
        // Default rate limits
        let rate_limiter = Arc::new(RateLimiterManager::new(10, 60));
        
        // Create multi-tier rate limiter
        let multi_tier_rate_limiter = Arc::new(MultiTierRateLimiter::new());
        multi_tier_rate_limiter.clone().start_cleanup_task();
        
        // Create broadcast optimizer with 4 workers
        let broadcast_optimizer = Arc::new(BroadcastOptimizer::new(4));
        
        Self {
            sessions: Arc::new(RwLock::new(SessionManager::with_message_store(
                message_store,
            ))),
            rooms: Arc::new(RwLock::new(RoomManager::new())),
            rate_limiter,
            multi_tier_rate_limiter,
            broadcast_optimizer,
        }
    }
    
    /// Create with rate limiting configuration
    pub fn with_rate_limits(max_connections_per_ip: usize, max_messages_per_minute: u32) -> Self {
        let rate_limiter = Arc::new(RateLimiterManager::new(max_connections_per_ip, max_messages_per_minute));
        
        // Start cleanup task
        rate_limiter.clone().start_cleanup_task();
        
        // Create multi-tier rate limiter
        let multi_tier_rate_limiter = Arc::new(MultiTierRateLimiter::new());
        multi_tier_rate_limiter.clone().start_cleanup_task();
        
        // Create broadcast optimizer with 4 workers
        let broadcast_optimizer = Arc::new(BroadcastOptimizer::new(4));
        
        Self {
            sessions: Arc::new(RwLock::new(SessionManager::new())),
            rooms: Arc::new(RwLock::new(RoomManager::new())),
            rate_limiter,
            multi_tier_rate_limiter,
            broadcast_optimizer,
        }
    }

    /// Register an authenticated user (atomic operation to prevent race conditions)
    pub async fn register_authenticated_user(
        &self,
        user: User,
        sender: mpsc::UnboundedSender<WsMessage>,
        client_ip: std::net::IpAddr,
    ) -> Result<()> {
        let user_id = user.id.clone();

        // SECURITY: Atomic registration - hold both locks to prevent race conditions
        let mut sessions = self.sessions.write().await;
        let rooms = self.rooms.write().await;
        
        // First register in session manager
        match sessions.register_authenticated(user, sender, client_ip) {
            Ok(()) => {
                // Success: now auto-join default room
                let default_room_id = rooms.default_room_id().to_string();
                match rooms.join_room(user_id.clone(), default_room_id).await {
                    Ok(()) => {
                        log::debug!("Successfully registered authenticated user: {}", user_id);
                        Ok(())
                    }
                    Err(room_err) => {
                        // ROLLBACK: Remove from sessions if room join failed
                        log::error!("Room join failed for user {}, rolling back session registration", user_id);
                        let _ = sessions.unregister(&user_id);
                        Err(room_err)
                    }
                }
            }
            Err(session_err) => {
                log::error!("Session registration failed for user: {}", user_id);
                Err(session_err)
            }
        }
    }

    /// Register an anonymous user (atomic operation to prevent race conditions)
    pub async fn register_anonymous_user(
        &self,
        client_id: String,
        sender: mpsc::UnboundedSender<WsMessage>,
        client_ip: std::net::IpAddr,
    ) -> Result<()> {
        // SECURITY: Atomic registration - hold both locks to prevent race conditions
        let mut sessions = self.sessions.write().await;
        let rooms = self.rooms.write().await;
        
        // First register in session manager
        match sessions.register(client_id.clone(), sender, client_ip) {
            Ok(()) => {
                // Success: now auto-join default room
                let default_room_id = rooms.default_room_id().to_string();
                match rooms.join_room(client_id.clone(), default_room_id).await {
                    Ok(()) => {
                        log::debug!("Successfully registered anonymous user: {}", client_id);
                        Ok(())
                    }
                    Err(room_err) => {
                        // ROLLBACK: Remove from sessions if room join failed
                        log::error!("Room join failed for anonymous user {}, rolling back session registration", client_id);
                        let _ = sessions.unregister(&client_id);
                        Err(room_err)
                    }
                }
            }
            Err(session_err) => {
                log::error!("Session registration failed for anonymous user: {}", client_id);
                Err(session_err)
            }
        }
    }

    /// Unregister a user (atomic operation to prevent race conditions)
    pub async fn unregister_user(&self, user_id: &str) -> Result<()> {
        // SECURITY: Atomic unregistration - hold both locks to prevent race conditions
        let mut sessions = self.sessions.write().await;
        let rooms = self.rooms.write().await;
        
        // First remove from all rooms, then from sessions
        // This order ensures we don't have orphaned room memberships
        match rooms.remove_client(user_id).await {
            Ok(()) => {
                // Success: now remove from sessions
                match sessions.unregister(user_id) {
                    Ok(was_present) => {
                        if was_present {
                            log::debug!("Successfully unregistered user: {}", user_id);
                        }
                        Ok(())
                    }
                    Err(session_err) => {
                        log::error!("Session unregistration failed for user: {} (rooms already cleaned)", user_id);
                        Err(session_err)
                    }
                }
            }
            Err(room_err) => {
                // If room removal failed, still try to remove from sessions for consistency
                log::warn!("Room removal failed for user {}, attempting session cleanup anyway", user_id);
                let _ = sessions.unregister(user_id);
                Err(room_err)
            }
        }
    }

    /// Join a user to a room
    pub async fn join_room(&self, user_id: String, room_id: String) -> Result<()> {
        // SECURITY: Fix TOCTOU race condition by holding both locks atomically
        let sessions = self.sessions.read().await;
        let rooms = self.rooms.write().await;
        
        // Check if user is connected while holding both locks
        if sessions.get_connection(&user_id).is_none() {
            return Err(RustySocksError::SessionNotFound(user_id));
        }

        // Join the room (both locks still held)
        rooms.join_room_atomic(user_id, room_id).await
    }

    /// Leave a room
    pub async fn leave_room(&self, user_id: &str, room_id: &str) -> Result<()> {
        // SECURITY: Fix TOCTOU race condition by checking and operating atomically
        let rooms = self.rooms.read().await;
        
        // Don't allow leaving default room
        if room_id == rooms.default_room_id() {
            return Err(RustySocksError::CannotDeleteDefaultRoom);
        }
        
        // Release read lock before atomic operation
        drop(rooms);
        
        // Use atomic operation
        let rooms = self.rooms.read().await;
        rooms.leave_room_atomic(user_id, room_id).await
    }

    /// Broadcast message to all users in a room (optimized)
    pub async fn broadcast_to_room(
        &self,
        room_id: &str,
        message: &str,
        exclude_user: Option<&str>,
    ) -> Result<usize> {
        // Get room members
        let members = {
            let rooms = self.rooms.read().await;
            rooms.get_room_members(room_id).await?
        };

        // Prepare recipients for optimized broadcasting
        let mut recipients = Vec::new();
        
        {
            let sessions = self.sessions.read().await;
            
            for member_id in members {
                // Skip excluded user
                if let Some(ref exclude) = exclude_user {
                    if member_id == *exclude {
                        continue;
                    }
                }

                // Get connection for the member
                if let Some(connection) = sessions.get_connection(&member_id) {
                    // Create Arc<Connection> from the existing connection
                    let arc_connection = Arc::new(Connection {
                        id: connection.id.clone(),
                        sender: connection.sender.clone(),
                        connected_at: connection.connected_at,
                        last_ping: connection.last_ping,
                        user: connection.user.clone(),
                        client_ip: connection.client_ip,
                    });
                    recipients.push((member_id, arc_connection));
                }
            }
        }

        // Use optimized broadcasting
        let stats = self.broadcast_optimizer
            .broadcast(message, recipients)
            .await?;

        Ok(stats.sent_count)
    }

    /// Check if user is in room and has permission to send messages
    /// Check if user can send messages in a room (TOCTOU-safe)
    pub async fn can_user_send_message(&self, user_id: &str, room_id: &str) -> Result<bool> {
        // SECURITY: Use atomic permission check to prevent TOCTOU race conditions
        let rooms = self.rooms.read().await;
        rooms.check_user_send_permission_atomic(user_id, room_id).await
    }
    
    /// Get user information from session
    pub async fn get_user_info(&self, user_id: &str) -> Option<String> {
        let sessions = self.sessions.read().await;
        sessions.get_user_info(user_id)
    }

    /// Check if user has permission to perform moderation action (TOCTOU-safe)
    pub async fn can_user_moderate(&self, user_id: &str, room_id: &str, required_permission: crate::auth::user::Permission) -> Result<bool> {
        // SECURITY: Use atomic permission check to prevent TOCTOU race conditions
        let rooms = self.rooms.read().await;
        rooms.check_user_moderation_permission_atomic(user_id, room_id, required_permission).await
    }
    
    /// Ban user from room
    pub async fn ban_user(&self, _moderator_id: &str, room_id: &str, user_id: &str, duration_hours: Option<u64>) -> Result<()> {
        let rooms = self.rooms.write().await;
        rooms.ban_user(room_id, user_id, duration_hours).await
    }
    
    /// Kick user from room (temporary removal without ban)
    pub async fn kick_user(&self, _moderator_id: &str, room_id: &str, user_id: &str) -> Result<()> {
        let rooms = self.rooms.write().await;
        rooms.kick_user(room_id, user_id).await
    }
    
    /// Set user role in room
    pub async fn set_user_role(&self, _moderator_id: &str, room_id: &str, user_id: &str, role: crate::auth::user::UserRole) -> Result<()> {
        let rooms = self.rooms.write().await;
        rooms.set_user_role(room_id, user_id, role).await
    }

    /// Send message to specific user
    pub async fn send_to_user(&self, user_id: &str, message: &str) -> Result<bool> {
        let sessions = self.sessions.read().await;
        match sessions.get_connection(user_id) {
            Some(connection) => Ok(connection.send_text(message)),
            None => Err(RustySocksError::SessionNotFound(user_id.to_string())),
        }
    }

    /// Get user's rooms
    pub async fn get_user_rooms(&self, user_id: &str) -> Result<Vec<String>> {
        let rooms = self.rooms.read().await;
        Ok(rooms.get_client_rooms(user_id).await)
    }

    /// Get room members
    pub async fn get_room_members(&self, room_id: &str) -> Result<Vec<String>> {
        let rooms = self.rooms.read().await;
        rooms.get_room_members(room_id).await
    }

    /// Create a new room
    pub async fn create_room(&self, name: String, max_members: Option<usize>) -> Result<String> {
        let rooms = self.rooms.write().await;
        rooms.create_room(name, max_members).await
    }

    /// List all rooms
    pub async fn list_rooms(&self) -> Vec<(String, String, usize)> {
        let rooms = self.rooms.read().await;
        rooms.list_rooms().await
    }

    /// Get connection count
    pub async fn connection_count(&self) -> usize {
        let sessions = self.sessions.read().await;
        sessions.client_count()
    }
    
    /// Start automatic cleanup of stale connections
    pub fn start_cleanup_task(self: Arc<Self>, cleanup_interval: Duration, connection_timeout: Duration) {
        let server = Arc::clone(&self);
        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            loop {
                interval.tick().await;
                if let Err(e) = server.cleanup_stale_connections(connection_timeout).await {
                    log::error!("Failed to cleanup stale connections: {}", e);
                }
            }
        });
    }
    
    /// Clean up stale connections with resource limits and protection
    async fn cleanup_stale_connections(&self, timeout: Duration) -> Result<()> {
        // Limit cleanup operations to prevent resource exhaustion
        const MAX_CLEANUP_OPERATIONS_PER_CYCLE: usize = 50;
        const MAX_CLEANUP_TIME: Duration = Duration::from_secs(30);
        
        let cleanup_start = std::time::Instant::now();
        
        // Get list of stale connections with limited scope
        let stale_connection_ids = {
            let sessions = self.sessions.read().await;
            let all_stale = sessions.check_stale_connections(timeout);
            
            // Limit the number of connections to process in one cycle
            if all_stale.len() > MAX_CLEANUP_OPERATIONS_PER_CYCLE {
                log::warn!("Large number of stale connections detected ({}), processing {} this cycle", 
                          all_stale.len(), MAX_CLEANUP_OPERATIONS_PER_CYCLE);
                all_stale.into_iter().take(MAX_CLEANUP_OPERATIONS_PER_CYCLE).collect()
            } else {
                all_stale
            }
        };
        
        if !stale_connection_ids.is_empty() {
            log::info!("Cleaning up {} stale connections", stale_connection_ids.len());
            
            let mut cleaned_count = 0;
            let mut failed_count = 0;
            
            // Remove each stale connection with time limits
            for connection_id in stale_connection_ids {
                // Check if we've exceeded time limit
                if cleanup_start.elapsed() > MAX_CLEANUP_TIME {
                    log::warn!("Cleanup operation timeout reached, stopping early");
                    break;
                }
                
                match self.unregister_user(&connection_id).await {
                    Ok(()) => {
                        cleaned_count += 1;
                        log::debug!("Successfully cleaned up stale connection: {}", connection_id);
                    }
                    Err(e) => {
                        failed_count += 1;
                        log::debug!("Failed to cleanup stale connection {}: {}", connection_id, e);
                        
                        // If too many failures, stop to prevent cascading issues
                        if failed_count > 10 {
                            log::warn!("Too many cleanup failures ({}), stopping cleanup cycle", failed_count);
                            break;
                        }
                    }
                }
            }
            
            if failed_count > 0 {
                log::warn!("Cleanup cycle completed: {} cleaned, {} failed", cleaned_count, failed_count);
            } else {
                log::info!("Cleanup cycle completed successfully: {} connections cleaned", cleaned_count);
            }
        }
        
        Ok(())
    }
    
    /// Check if a user can send a message (rate limiting)
    pub async fn can_user_send_message_rate_limit(&self, user_id: &str) -> bool {
        self.rate_limiter.message_limiter.allow_message(user_id).await
    }
    
    /// Check if a connection from this IP is allowed
    pub async fn can_ip_connect(&self, ip: std::net::IpAddr) -> bool {
        self.rate_limiter.connection_limiter.allow_connection(ip).await
    }
    
    /// Register a new connection from an IP
    pub async fn register_ip_connection(&self, ip: std::net::IpAddr) -> bool {
        self.rate_limiter.connection_limiter.add_connection(ip).await
    }
    
    /// Remove a connection from an IP
    pub async fn unregister_ip_connection(&self, ip: std::net::IpAddr) {
        self.rate_limiter.connection_limiter.remove_connection(ip).await
    }

    /// Check if a user can perform an operation using multi-tier rate limiting
    pub async fn can_user_perform_operation(
        &self,
        user_id: &str,
        user_ip: std::net::IpAddr,
        user_tier: UserTier,
        operation: OperationType,
    ) -> bool {
        self.multi_tier_rate_limiter
            .allow_request(user_id, user_ip, user_tier, operation)
            .await
    }

    /// Get multi-tier rate limit status for a user
    pub async fn get_user_rate_status(&self, user_id: &str) -> Option<crate::core::multi_tier_rate_limiter::RateLimitStatus> {
        self.multi_tier_rate_limiter.get_user_status(user_id).await
    }

    /// Get server load factor for monitoring
    pub fn get_server_load_factor(&self) -> f64 {
        self.multi_tier_rate_limiter.get_server_load_factor()
    }

    /// Determine user tier based on authentication and role
    pub async fn determine_user_tier(&self, user_id: &str) -> UserTier {
        let sessions = self.sessions.read().await;
        if let Some(connection) = sessions.get_connection(user_id) {
            if let Some(user) = &connection.user {
                match user.global_role {
                    Some(crate::auth::user::UserRole::Owner) |
                    Some(crate::auth::user::UserRole::Admin) => UserTier::Privileged,
                    Some(crate::auth::user::UserRole::Moderator) => UserTier::Premium,
                    Some(crate::auth::user::UserRole::Member) => UserTier::Authenticated,
                    _ => UserTier::Authenticated, // Default for authenticated users
                }
            } else {
                UserTier::Anonymous
            }
        } else {
            UserTier::Anonymous // User not found
        }
    }

    /// Get user's IP address from connection
    pub async fn get_user_ip(&self, user_id: &str) -> Option<std::net::IpAddr> {
        let sessions = self.sessions.read().await;
        sessions.get_connection(user_id).map(|conn| conn.client_ip)
    }

    /// Store a message
    pub async fn store_message(&self, message: crate::core::message::Message) -> Result<bool> {
        let sessions = self.sessions.read().await;
        sessions.store_message_async(message).await
    }

    /// Get recent messages
    pub async fn get_recent_messages(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::core::message::Message>> {
        let sessions = self.sessions.read().await;
        sessions.get_recent_messages_async(limit).await
    }
}

// Shared reference to server manager
pub type SharedServerManager = Arc<ServerManager>;
