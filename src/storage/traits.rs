//! Abstract storage interfaces for pluggable backends
//! 
//! This module defines traits for different storage backends including
//! message storage, user data, room persistence, and session management.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::auth::user::UserRole;
// use crate::core::message::Message; // Currently unused
use crate::error::Result;

/// Metadata for stored messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub room_id: String,
    pub sender_id: String,
    pub sender_username: String,
    pub content: String,
    pub message_type: String,
    pub timestamp: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
    pub edited_at: Option<DateTime<Utc>>,
    pub reply_to: Option<String>,
}

/// Room data for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRoom {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub max_members: Option<usize>,
    pub is_private: bool,
    pub password_hash: Option<String>,
    pub settings: HashMap<String, String>,
}

/// User profile data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
    pub profile_data: HashMap<String, String>,
    pub preferences: HashMap<String, String>,
}

/// User role assignment in a room
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRoleAssignment {
    pub user_id: String,
    pub room_id: String,
    pub role: UserRole,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: String,
}

/// Ban record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanRecord {
    pub id: String,
    pub user_id: String,
    pub room_id: Option<String>, // None for global ban
    pub banned_by: String,
    pub reason: Option<String>,
    pub banned_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// Message storage interface
#[async_trait]
pub trait MessageStorage: Send + Sync {
    /// Store a new message
    async fn store_message(&self, message: StoredMessage) -> Result<String>;
    
    /// Get messages from a room with pagination
    async fn get_room_messages(
        &self,
        room_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredMessage>>;
    
    /// Get messages after a specific timestamp
    async fn get_messages_since(
        &self,
        room_id: &str,
        since: DateTime<Utc>,
    ) -> Result<Vec<StoredMessage>>;
    
    /// Update a message (for edits)
    async fn update_message(&self, message_id: &str, new_content: String) -> Result<()>;
    
    /// Delete a message
    async fn delete_message(&self, message_id: &str) -> Result<()>;
    
    /// Search messages by content
    async fn search_messages(
        &self,
        room_id: Option<&str>,
        query: &str,
        limit: usize,
    ) -> Result<Vec<StoredMessage>>;
    
    /// Get message count for a room
    async fn get_message_count(&self, room_id: &str) -> Result<usize>;
    
    /// Clean up old messages (for retention policies)
    async fn cleanup_old_messages(&self, older_than: DateTime<Utc>) -> Result<usize>;
}

/// Room data storage interface
#[async_trait]
pub trait RoomStorage: Send + Sync {
    /// Create a new room
    async fn create_room(&self, room: StoredRoom) -> Result<String>;
    
    /// Get room by ID
    async fn get_room(&self, room_id: &str) -> Result<Option<StoredRoom>>;
    
    /// Update room data
    async fn update_room(&self, room: StoredRoom) -> Result<()>;
    
    /// Delete a room
    async fn delete_room(&self, room_id: &str) -> Result<()>;
    
    /// List all rooms
    async fn list_rooms(&self, offset: usize, limit: usize) -> Result<Vec<StoredRoom>>;
    
    /// Search rooms by name
    async fn search_rooms(&self, query: &str, limit: usize) -> Result<Vec<StoredRoom>>;
    
    /// Get rooms created by a user
    async fn get_user_created_rooms(&self, user_id: &str) -> Result<Vec<StoredRoom>>;
}

/// User data storage interface
#[async_trait]
pub trait UserStorage: Send + Sync {
    /// Create a new user
    async fn create_user(&self, user: StoredUser) -> Result<String>;
    
    /// Get user by ID
    async fn get_user(&self, user_id: &str) -> Result<Option<StoredUser>>;
    
    /// Get user by username
    async fn get_user_by_username(&self, username: &str) -> Result<Option<StoredUser>>;
    
    /// Get user by email
    async fn get_user_by_email(&self, email: &str) -> Result<Option<StoredUser>>;
    
    /// Update user data
    async fn update_user(&self, user: StoredUser) -> Result<()>;
    
    /// Update user's last active timestamp
    async fn update_last_active(&self, user_id: &str) -> Result<()>;
    
    /// Delete a user
    async fn delete_user(&self, user_id: &str) -> Result<()>;
    
    /// Search users by username
    async fn search_users(&self, query: &str, limit: usize) -> Result<Vec<StoredUser>>;
}

/// Role and permissions storage interface
#[async_trait]
pub trait RoleStorage: Send + Sync {
    /// Assign role to user in room
    async fn assign_role(&self, assignment: UserRoleAssignment) -> Result<()>;
    
    /// Get user's role in a room
    async fn get_user_role(&self, user_id: &str, room_id: &str) -> Result<Option<UserRole>>;
    
    /// Get all role assignments for a user
    async fn get_user_roles(&self, user_id: &str) -> Result<Vec<UserRoleAssignment>>;
    
    /// Get all users with roles in a room
    async fn get_room_roles(&self, room_id: &str) -> Result<Vec<UserRoleAssignment>>;
    
    /// Remove role assignment
    async fn remove_role(&self, user_id: &str, room_id: &str) -> Result<()>;
    
    /// Remove all role assignments for a user
    async fn remove_user_roles(&self, user_id: &str) -> Result<()>;
    
    /// Remove all role assignments for a room
    async fn remove_room_roles(&self, room_id: &str) -> Result<()>;
}

/// Ban and moderation storage interface
#[async_trait]
pub trait ModerationStorage: Send + Sync {
    /// Create a ban record
    async fn create_ban(&self, ban: BanRecord) -> Result<String>;
    
    /// Get active bans for a user
    async fn get_user_bans(&self, user_id: &str) -> Result<Vec<BanRecord>>;
    
    /// Check if user is banned from a room
    async fn is_user_banned(&self, user_id: &str, room_id: Option<&str>) -> Result<bool>;
    
    /// Lift/deactivate a ban
    async fn lift_ban(&self, ban_id: &str) -> Result<()>;
    
    /// Get all active bans for a room
    async fn get_room_bans(&self, room_id: &str) -> Result<Vec<BanRecord>>;
    
    /// Cleanup expired bans
    async fn cleanup_expired_bans(&self) -> Result<usize>;
}

/// Analytics and metrics storage interface
#[async_trait]
pub trait AnalyticsStorage: Send + Sync {
    /// Record a metric event
    async fn record_event(&self, event_type: &str, data: HashMap<String, String>) -> Result<()>;
    
    /// Get event count for a type within a time range
    async fn get_event_count(
        &self,
        event_type: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<u64>;
    
    /// Get top active users by message count
    async fn get_top_users(&self, limit: usize, timeframe_hours: u64) -> Result<Vec<(String, u64)>>;
    
    /// Get room activity statistics
    async fn get_room_stats(&self, room_id: &str, timeframe_hours: u64) -> Result<RoomStats>;
    
    /// Get server-wide statistics
    async fn get_server_stats(&self, timeframe_hours: u64) -> Result<ServerStats>;
}

/// Room activity statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomStats {
    pub room_id: String,
    pub message_count: u64,
    pub unique_users: u64,
    pub peak_concurrent_users: u64,
    pub average_messages_per_user: f64,
}

/// Server-wide statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStats {
    pub total_messages: u64,
    pub total_users: u64,
    pub total_rooms: u64,
    pub active_connections: u64,
    pub peak_concurrent_connections: u64,
    pub uptime_hours: f64,
}

/// Combined storage provider interface
#[async_trait]
pub trait StorageProvider: Send + Sync {
    /// Get message storage backend
    fn message_storage(&self) -> &dyn MessageStorage;
    
    /// Get room storage backend
    fn room_storage(&self) -> &dyn RoomStorage;
    
    /// Get user storage backend
    fn user_storage(&self) -> &dyn UserStorage;
    
    /// Get role storage backend
    fn role_storage(&self) -> &dyn RoleStorage;
    
    /// Get moderation storage backend
    fn moderation_storage(&self) -> &dyn ModerationStorage;
    
    /// Get analytics storage backend (optional)
    fn analytics_storage(&self) -> Option<&dyn AnalyticsStorage> {
        None
    }
    
    /// Initialize the storage backend (create tables, etc.)
    async fn initialize(&self) -> Result<()>;
    
    /// Health check for the storage backend
    async fn health_check(&self) -> Result<bool>;
    
    /// Backup data (if supported)
    async fn backup(&self, _destination: &str) -> Result<()> {
        Err(crate::error::RustySocksError::NotImplemented(
            "Backup not implemented for this storage provider".to_string()
        ))
    }
    
    /// Restore data (if supported)
    async fn restore(&self, _source: &str) -> Result<()> {
        Err(crate::error::RustySocksError::NotImplemented(
            "Restore not implemented for this storage provider".to_string()
        ))
    }
}

/// Configuration for storage providers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub provider_type: String,
    pub connection_string: Option<String>,
    pub settings: HashMap<String, String>,
}

impl StorageConfig {
    pub fn memory() -> Self {
        Self {
            provider_type: "memory".to_string(),
            connection_string: None,
            settings: HashMap::new(),
        }
    }
    
    pub fn sqlite(db_path: &str) -> Self {
        let mut settings = HashMap::new();
        settings.insert("db_path".to_string(), db_path.to_string());
        
        Self {
            provider_type: "sqlite".to_string(),
            connection_string: Some(format!("sqlite://{}", db_path)),
            settings,
        }
    }
    
    pub fn postgresql(connection_string: &str) -> Self {
        Self {
            provider_type: "postgresql".to_string(),
            connection_string: Some(connection_string.to_string()),
            settings: HashMap::new(),
        }
    }
    
    pub fn redis(connection_string: &str) -> Self {
        Self {
            provider_type: "redis".to_string(),
            connection_string: Some(connection_string.to_string()),
            settings: HashMap::new(),
        }
    }
}