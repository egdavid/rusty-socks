//! Integrated server service that coordinates sessions and rooms

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use warp::ws::Message as WsMessage;

use crate::auth::user::User;
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
}

impl ServerManager {
    /// Create a new server manager
    pub fn new() -> Self {
        // Default rate limits
        let rate_limiter = Arc::new(RateLimiterManager::new(10, 60));
        
        Self {
            sessions: Arc::new(RwLock::new(SessionManager::new())),
            rooms: Arc::new(RwLock::new(RoomManager::new())),
            rate_limiter,
        }
    }

    /// Create with message store
    pub fn with_message_store(message_store: SharedMessageStore) -> Self {
        // Default rate limits
        let rate_limiter = Arc::new(RateLimiterManager::new(10, 60));
        
        Self {
            sessions: Arc::new(RwLock::new(SessionManager::with_message_store(
                message_store,
            ))),
            rooms: Arc::new(RwLock::new(RoomManager::new())),
            rate_limiter,
        }
    }
    
    /// Create with rate limiting configuration
    pub fn with_rate_limits(max_connections_per_ip: usize, max_messages_per_minute: u32) -> Self {
        let rate_limiter = Arc::new(RateLimiterManager::new(max_connections_per_ip, max_messages_per_minute));
        
        // Start cleanup task
        rate_limiter.clone().start_cleanup_task();
        
        Self {
            sessions: Arc::new(RwLock::new(SessionManager::new())),
            rooms: Arc::new(RwLock::new(RoomManager::new())),
            rate_limiter,
        }
    }

    /// Register an authenticated user
    pub async fn register_authenticated_user(
        &self,
        user: User,
        sender: mpsc::UnboundedSender<WsMessage>,
    ) -> Result<()> {
        let user_id = user.id.clone();

        // Register in session manager
        {
            let mut sessions = self.sessions.write().await;
            sessions.register_authenticated(user, sender)?;
        }

        // Auto-join default room
        {
            let rooms = self.rooms.write().await;
            let default_room_id = rooms.default_room_id().to_string();
            rooms.join_room(user_id, default_room_id).await?;
        }

        Ok(())
    }

    /// Register an anonymous user
    pub async fn register_anonymous_user(
        &self,
        client_id: String,
        sender: mpsc::UnboundedSender<WsMessage>,
    ) -> Result<()> {
        // Register in session manager
        {
            let mut sessions = self.sessions.write().await;
            sessions.register(client_id.clone(), sender)?;
        }

        // Auto-join default room
        {
            let rooms = self.rooms.write().await;
            let default_room_id = rooms.default_room_id().to_string();
            rooms.join_room(client_id, default_room_id).await?;
        }

        Ok(())
    }

    /// Unregister a user (removes from sessions and all rooms)
    pub async fn unregister_user(&self, user_id: &str) -> Result<()> {
        // Remove from all rooms first
        {
            let rooms = self.rooms.write().await;
            rooms.remove_client(user_id).await?;
        }

        // Remove from sessions
        {
            let mut sessions = self.sessions.write().await;
            sessions.unregister(user_id)?;
        }

        Ok(())
    }

    /// Join a user to a room
    pub async fn join_room(&self, user_id: String, room_id: String) -> Result<()> {
        // Check if user is connected
        {
            let sessions = self.sessions.read().await;
            if sessions.get_connection(&user_id).is_none() {
                return Err(RustySocksError::SessionNotFound(user_id));
            }
        }

        // Join the room
        let rooms = self.rooms.write().await;
        rooms.join_room(user_id, room_id).await
    }

    /// Leave a room
    pub async fn leave_room(&self, user_id: &str, room_id: &str) -> Result<()> {
        // Use write lock from the start to avoid race condition
        let rooms = self.rooms.write().await;
        
        // Don't allow leaving default room
        if room_id == rooms.default_room_id() {
            return Err(RustySocksError::CannotDeleteDefaultRoom);
        }
        
        rooms.leave_room(user_id, room_id).await
    }

    /// Broadcast message to all users in a room (async concurrent)
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

        // Prepare tasks for concurrent sending
        let mut send_tasks = Vec::new();
        let message = message.to_string(); // Clone for moving into tasks
        let exclude_user = exclude_user.map(|s| s.to_string());
        
        {
            let sessions = self.sessions.read().await;
            
            for member_id in members {
                // Skip excluded user
                if let Some(ref exclude) = exclude_user {
                    if member_id == *exclude {
                        continue;
                    }
                }

                // Get connection and create send task
                if let Some(connection) = sessions.get_connection(&member_id) {
                    let message_clone = message.clone();
                    let member_id_clone = member_id.clone();
                    let connection_sender = connection.sender.clone();
                    
                    // Create async task for each send operation
                    let task = tokio::spawn(async move {
                        match connection_sender.send(WsMessage::text(message_clone)) {
                            Ok(_) => {
                                log::trace!("Message sent to user: {}", member_id_clone);
                                true
                            }
                            Err(e) => {
                                log::warn!("Failed to send message to user {}: {}", member_id_clone, e);
                                false
                            }
                        }
                    });
                    
                    send_tasks.push(task);
                }
            }
        }

        // Wait for all send operations to complete concurrently
        let results = futures_util::future::join_all(send_tasks).await;
        
        // Count successful sends
        let sent_count = results
            .into_iter()
            .filter_map(|result| result.ok()) // Handle task join errors
            .filter(|&success| success)       // Count successful sends
            .count();

        Ok(sent_count)
    }

    /// Check if user is in room and has permission to send messages
    pub async fn can_user_send_message(&self, user_id: &str, room_id: &str) -> Result<bool> {
        let rooms = self.rooms.read().await;
        
        // Check if user is in the room
        if !rooms.is_user_in_room(user_id, room_id).await? {
            return Ok(false);
        }
        
        // Check if user is banned
        if rooms.is_user_banned(user_id, room_id).await? {
            return Ok(false);
        }
        
        // Check if user is muted
        if rooms.is_user_muted(user_id, room_id).await? {
            return Ok(false);
        }
        
        // Check if user has SendMessages permission
        let user_role = rooms.get_user_role(user_id, room_id).await?;
        if let Some(role) = user_role {
            Ok(role.has_permission(crate::auth::user::Permission::SendMessages))
        } else {
            // If no specific role, assume Guest permissions
            Ok(crate::auth::user::UserRole::Guest.has_permission(crate::auth::user::Permission::SendMessages))
        }
    }
    
    /// Get user information from session
    pub async fn get_user_info(&self, user_id: &str) -> Option<String> {
        let sessions = self.sessions.read().await;
        sessions.get_user_info(user_id)
    }

    /// Check if user has permission to perform moderation action
    pub async fn can_user_moderate(&self, user_id: &str, room_id: &str, required_permission: crate::auth::user::Permission) -> Result<bool> {
        let rooms = self.rooms.read().await;
        
        // Check if user is in the room
        if !rooms.is_user_in_room(user_id, room_id).await? {
            return Ok(false);
        }
        
        // Get user role in room
        let user_role = rooms.get_user_role(user_id, room_id).await?;
        if let Some(role) = user_role {
            Ok(role.has_permission(required_permission))
        } else {
            // If no specific role, assume Guest permissions (can't moderate)
            Ok(false)
        }
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

    /// Store a message
    pub async fn store_message(&self, message: crate::core::message::Message) -> Result<bool> {
        let sessions = self.sessions.read().await;
        sessions.store_message(message)
    }

    /// Get recent messages
    pub async fn get_recent_messages(
        &self,
        limit: usize,
    ) -> Result<Vec<crate::core::message::Message>> {
        let sessions = self.sessions.read().await;
        sessions.get_recent_messages(limit)
    }
}

// Shared reference to server manager
pub type SharedServerManager = Arc<ServerManager>;
