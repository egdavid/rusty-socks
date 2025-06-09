//! In-memory storage implementation for development and testing
//! 
//! This provides a complete storage implementation that keeps all data
//! in memory. Suitable for development, testing, or small deployments.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::traits::*;
use crate::auth::user::UserRole;
use crate::error::{Result, RustySocksError};

/// In-memory message storage
pub struct MemoryMessageStorage {
    messages: Arc<RwLock<HashMap<String, StoredMessage>>>,
    room_messages: Arc<RwLock<HashMap<String, Vec<String>>>>, // room_id -> message_ids
    next_id: Arc<RwLock<u64>>,
}

impl MemoryMessageStorage {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(RwLock::new(HashMap::new())),
            room_messages: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(1)),
        }
    }
    
    async fn generate_id(&self) -> String {
        let mut id = self.next_id.write().await;
        let current = *id;
        *id += 1;
        format!("msg_{}", current)
    }
}

#[async_trait]
impl MessageStorage for MemoryMessageStorage {
    async fn store_message(&self, mut message: StoredMessage) -> Result<String> {
        let id = self.generate_id().await;
        message.id = id.clone();
        
        // Store the message
        self.messages.write().await.insert(id.clone(), message.clone());
        
        // Add to room index
        self.room_messages
            .write()
            .await
            .entry(message.room_id.clone())
            .or_insert_with(Vec::new)
            .push(id.clone());
        
        Ok(id)
    }
    
    async fn get_room_messages(
        &self,
        room_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredMessage>> {
        let room_messages = self.room_messages.read().await;
        let messages = self.messages.read().await;
        
        if let Some(message_ids) = room_messages.get(room_id) {
            let mut result = Vec::new();
            
            // Sort by timestamp (newest first for pagination)
            let mut sorted_messages: Vec<&StoredMessage> = message_ids
                .iter()
                .filter_map(|id| messages.get(id))
                .collect();
            
            sorted_messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            
            // Apply pagination
            for message in sorted_messages.iter().skip(offset).take(limit) {
                result.push((*message).clone());
            }
            
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }
    
    async fn get_messages_since(
        &self,
        room_id: &str,
        since: DateTime<Utc>,
    ) -> Result<Vec<StoredMessage>> {
        let room_messages = self.room_messages.read().await;
        let messages = self.messages.read().await;
        
        if let Some(message_ids) = room_messages.get(room_id) {
            let result: Vec<StoredMessage> = message_ids
                .iter()
                .filter_map(|id| messages.get(id))
                .filter(|msg| msg.timestamp > since)
                .cloned()
                .collect();
            
            Ok(result)
        } else {
            Ok(Vec::new())
        }
    }
    
    async fn update_message(&self, message_id: &str, new_content: String) -> Result<()> {
        let mut messages = self.messages.write().await;
        
        if let Some(message) = messages.get_mut(message_id) {
            message.content = new_content;
            message.edited_at = Some(Utc::now());
            Ok(())
        } else {
            Err(RustySocksError::NotFound(format!("Message {} not found", message_id)))
        }
    }
    
    async fn delete_message(&self, message_id: &str) -> Result<()> {
        let mut messages = self.messages.write().await;
        let mut room_messages = self.room_messages.write().await;
        
        if let Some(message) = messages.remove(message_id) {
            // Remove from room index
            if let Some(room_message_ids) = room_messages.get_mut(&message.room_id) {
                room_message_ids.retain(|id| id != message_id);
            }
            Ok(())
        } else {
            Err(RustySocksError::NotFound(format!("Message {} not found", message_id)))
        }
    }
    
    async fn search_messages(
        &self,
        room_id: Option<&str>,
        query: &str,
        limit: usize,
    ) -> Result<Vec<StoredMessage>> {
        let messages = self.messages.read().await;
        let room_messages = self.room_messages.read().await;
        
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();
        
        if let Some(room_id) = room_id {
            // Search within specific room
            if let Some(message_ids) = room_messages.get(room_id) {
                for id in message_ids {
                    if let Some(message) = messages.get(id) {
                        if message.content.to_lowercase().contains(&query_lower) {
                            results.push(message.clone());
                            if results.len() >= limit {
                                break;
                            }
                        }
                    }
                }
            }
        } else {
            // Search all messages
            for message in messages.values() {
                if message.content.to_lowercase().contains(&query_lower) {
                    results.push(message.clone());
                    if results.len() >= limit {
                        break;
                    }
                }
            }
        }
        
        // Sort by timestamp (newest first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        Ok(results)
    }
    
    async fn get_message_count(&self, room_id: &str) -> Result<usize> {
        let room_messages = self.room_messages.read().await;
        Ok(room_messages.get(room_id).map(|msgs| msgs.len()).unwrap_or(0))
    }
    
    async fn cleanup_old_messages(&self, older_than: DateTime<Utc>) -> Result<usize> {
        let mut messages = self.messages.write().await;
        let mut room_messages = self.room_messages.write().await;
        
        let mut deleted_count = 0;
        let mut to_delete = Vec::new();
        
        // Find messages to delete
        for (id, message) in messages.iter() {
            if message.timestamp < older_than {
                to_delete.push((id.clone(), message.room_id.clone()));
            }
        }
        
        // Delete the messages
        for (id, room_id) in to_delete {
            messages.remove(&id);
            if let Some(room_msg_ids) = room_messages.get_mut(&room_id) {
                room_msg_ids.retain(|msg_id| msg_id != &id);
            }
            deleted_count += 1;
        }
        
        Ok(deleted_count)
    }
}

/// In-memory combined storage provider
pub struct MemoryStorageProvider {
    message_storage: MemoryMessageStorage,
    rooms: Arc<RwLock<HashMap<String, StoredRoom>>>,
    users: Arc<RwLock<HashMap<String, StoredUser>>>,
    user_emails: Arc<RwLock<HashMap<String, String>>>, // email -> user_id
    user_usernames: Arc<RwLock<HashMap<String, String>>>, // username -> user_id
    roles: Arc<RwLock<HashMap<(String, String), UserRoleAssignment>>>, // (user_id, room_id) -> assignment
    bans: Arc<RwLock<HashMap<String, BanRecord>>>,
    analytics: Arc<RwLock<HashMap<String, Vec<(DateTime<Utc>, HashMap<String, String>)>>>>, // event_type -> events
}

impl MemoryStorageProvider {
    pub fn new() -> Self {
        Self {
            message_storage: MemoryMessageStorage::new(),
            rooms: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
            user_emails: Arc::new(RwLock::new(HashMap::new())),
            user_usernames: Arc::new(RwLock::new(HashMap::new())),
            roles: Arc::new(RwLock::new(HashMap::new())),
            bans: Arc::new(RwLock::new(HashMap::new())),
            analytics: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl StorageProvider for MemoryStorageProvider {
    fn message_storage(&self) -> &dyn MessageStorage {
        &self.message_storage
    }
    
    fn room_storage(&self) -> &dyn RoomStorage {
        self
    }
    
    fn user_storage(&self) -> &dyn UserStorage {
        self
    }
    
    fn role_storage(&self) -> &dyn RoleStorage {
        self
    }
    
    fn moderation_storage(&self) -> &dyn ModerationStorage {
        self
    }
    
    fn analytics_storage(&self) -> Option<&dyn AnalyticsStorage> {
        Some(self)
    }
    
    async fn initialize(&self) -> Result<()> {
        // Nothing to initialize for memory storage
        log::info!("Memory storage provider initialized");
        Ok(())
    }
    
    async fn health_check(&self) -> Result<bool> {
        // Memory storage is always healthy
        Ok(true)
    }
}

#[async_trait]
impl RoomStorage for MemoryStorageProvider {
    async fn create_room(&self, room: StoredRoom) -> Result<String> {
        let mut rooms = self.rooms.write().await;
        rooms.insert(room.id.clone(), room.clone());
        Ok(room.id)
    }
    
    async fn get_room(&self, room_id: &str) -> Result<Option<StoredRoom>> {
        let rooms = self.rooms.read().await;
        Ok(rooms.get(room_id).cloned())
    }
    
    async fn update_room(&self, room: StoredRoom) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        rooms.insert(room.id.clone(), room);
        Ok(())
    }
    
    async fn delete_room(&self, room_id: &str) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        if rooms.remove(room_id).is_some() {
            Ok(())
        } else {
            Err(RustySocksError::NotFound(format!("Room {} not found", room_id)))
        }
    }
    
    async fn list_rooms(&self, offset: usize, limit: usize) -> Result<Vec<StoredRoom>> {
        let rooms = self.rooms.read().await;
        let mut room_list: Vec<StoredRoom> = rooms.values().cloned().collect();
        room_list.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        
        Ok(room_list.into_iter().skip(offset).take(limit).collect())
    }
    
    async fn search_rooms(&self, query: &str, limit: usize) -> Result<Vec<StoredRoom>> {
        let rooms = self.rooms.read().await;
        let query_lower = query.to_lowercase();
        
        let mut results: Vec<StoredRoom> = rooms
            .values()
            .filter(|room| {
                room.name.to_lowercase().contains(&query_lower) ||
                room.description.as_ref().map_or(false, |desc| desc.to_lowercase().contains(&query_lower))
            })
            .cloned()
            .collect();
        
        results.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        results.truncate(limit);
        
        Ok(results)
    }
    
    async fn get_user_created_rooms(&self, user_id: &str) -> Result<Vec<StoredRoom>> {
        let rooms = self.rooms.read().await;
        let results: Vec<StoredRoom> = rooms
            .values()
            .filter(|room| room.created_by == user_id)
            .cloned()
            .collect();
        
        Ok(results)
    }
}

#[async_trait]
impl UserStorage for MemoryStorageProvider {
    async fn create_user(&self, user: StoredUser) -> Result<String> {
        let mut users = self.users.write().await;
        let mut emails = self.user_emails.write().await;
        let mut usernames = self.user_usernames.write().await;
        
        // Check for conflicts
        if usernames.contains_key(&user.username) {
            return Err(RustySocksError::ConflictError("Username already exists".to_string()));
        }
        
        if let Some(ref email) = user.email {
            if emails.contains_key(email) {
                return Err(RustySocksError::ConflictError("Email already exists".to_string()));
            }
            emails.insert(email.clone(), user.id.clone());
        }
        
        usernames.insert(user.username.clone(), user.id.clone());
        users.insert(user.id.clone(), user.clone());
        
        Ok(user.id)
    }
    
    async fn get_user(&self, user_id: &str) -> Result<Option<StoredUser>> {
        let users = self.users.read().await;
        Ok(users.get(user_id).cloned())
    }
    
    async fn get_user_by_username(&self, username: &str) -> Result<Option<StoredUser>> {
        let usernames = self.user_usernames.read().await;
        let users = self.users.read().await;
        
        if let Some(user_id) = usernames.get(username) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }
    
    async fn get_user_by_email(&self, email: &str) -> Result<Option<StoredUser>> {
        let emails = self.user_emails.read().await;
        let users = self.users.read().await;
        
        if let Some(user_id) = emails.get(email) {
            Ok(users.get(user_id).cloned())
        } else {
            Ok(None)
        }
    }
    
    async fn update_user(&self, user: StoredUser) -> Result<()> {
        let mut users = self.users.write().await;
        users.insert(user.id.clone(), user);
        Ok(())
    }
    
    async fn update_last_active(&self, user_id: &str) -> Result<()> {
        let mut users = self.users.write().await;
        if let Some(user) = users.get_mut(user_id) {
            user.last_active = Utc::now();
            Ok(())
        } else {
            Err(RustySocksError::NotFound(format!("User {} not found", user_id)))
        }
    }
    
    async fn delete_user(&self, user_id: &str) -> Result<()> {
        let mut users = self.users.write().await;
        let mut emails = self.user_emails.write().await;
        let mut usernames = self.user_usernames.write().await;
        
        if let Some(user) = users.remove(user_id) {
            usernames.remove(&user.username);
            if let Some(ref email) = user.email {
                emails.remove(email);
            }
            Ok(())
        } else {
            Err(RustySocksError::NotFound(format!("User {} not found", user_id)))
        }
    }
    
    async fn search_users(&self, query: &str, limit: usize) -> Result<Vec<StoredUser>> {
        let users = self.users.read().await;
        let query_lower = query.to_lowercase();
        
        let mut results: Vec<StoredUser> = users
            .values()
            .filter(|user| {
                user.username.to_lowercase().contains(&query_lower) ||
                user.email.as_ref().map_or(false, |email| email.to_lowercase().contains(&query_lower))
            })
            .cloned()
            .collect();
        
        results.sort_by(|a, b| a.username.cmp(&b.username));
        results.truncate(limit);
        
        Ok(results)
    }
}

#[async_trait]
impl RoleStorage for MemoryStorageProvider {
    async fn assign_role(&self, assignment: UserRoleAssignment) -> Result<()> {
        let mut roles = self.roles.write().await;
        let key = (assignment.user_id.clone(), assignment.room_id.clone());
        roles.insert(key, assignment);
        Ok(())
    }
    
    async fn get_user_role(&self, user_id: &str, room_id: &str) -> Result<Option<UserRole>> {
        let roles = self.roles.read().await;
        let key = (user_id.to_string(), room_id.to_string());
        Ok(roles.get(&key).map(|assignment| assignment.role))
    }
    
    async fn get_user_roles(&self, user_id: &str) -> Result<Vec<UserRoleAssignment>> {
        let roles = self.roles.read().await;
        let results: Vec<UserRoleAssignment> = roles
            .values()
            .filter(|assignment| assignment.user_id == user_id)
            .cloned()
            .collect();
        Ok(results)
    }
    
    async fn get_room_roles(&self, room_id: &str) -> Result<Vec<UserRoleAssignment>> {
        let roles = self.roles.read().await;
        let results: Vec<UserRoleAssignment> = roles
            .values()
            .filter(|assignment| assignment.room_id == room_id)
            .cloned()
            .collect();
        Ok(results)
    }
    
    async fn remove_role(&self, user_id: &str, room_id: &str) -> Result<()> {
        let mut roles = self.roles.write().await;
        let key = (user_id.to_string(), room_id.to_string());
        roles.remove(&key);
        Ok(())
    }
    
    async fn remove_user_roles(&self, user_id: &str) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles.retain(|(uid, _), _| uid != user_id);
        Ok(())
    }
    
    async fn remove_room_roles(&self, room_id: &str) -> Result<()> {
        let mut roles = self.roles.write().await;
        roles.retain(|(_, rid), _| rid != room_id);
        Ok(())
    }
}

#[async_trait]
impl ModerationStorage for MemoryStorageProvider {
    async fn create_ban(&self, ban: BanRecord) -> Result<String> {
        let mut bans = self.bans.write().await;
        let ban_id = ban.id.clone();
        bans.insert(ban_id.clone(), ban);
        Ok(ban_id)
    }
    
    async fn get_user_bans(&self, user_id: &str) -> Result<Vec<BanRecord>> {
        let bans = self.bans.read().await;
        let results: Vec<BanRecord> = bans
            .values()
            .filter(|ban| ban.user_id == user_id && ban.is_active)
            .cloned()
            .collect();
        Ok(results)
    }
    
    async fn is_user_banned(&self, user_id: &str, room_id: Option<&str>) -> Result<bool> {
        let bans = self.bans.read().await;
        let now = Utc::now();
        
        for ban in bans.values() {
            if ban.user_id == user_id && ban.is_active {
                // Check if ban is expired
                if let Some(expiry) = ban.expires_at {
                    if now > expiry {
                        continue; // Ban expired
                    }
                }
                
                // Check room match
                match (room_id, &ban.room_id) {
                    (Some(rid), Some(ban_rid)) => {
                        if rid == ban_rid {
                            return Ok(true); // Room-specific ban
                        }
                    }
                    (_, None) => return Ok(true), // Global ban
                    _ => continue,
                }
            }
        }
        
        Ok(false)
    }
    
    async fn lift_ban(&self, ban_id: &str) -> Result<()> {
        let mut bans = self.bans.write().await;
        if let Some(ban) = bans.get_mut(ban_id) {
            ban.is_active = false;
            Ok(())
        } else {
            Err(RustySocksError::NotFound(format!("Ban {} not found", ban_id)))
        }
    }
    
    async fn get_room_bans(&self, room_id: &str) -> Result<Vec<BanRecord>> {
        let bans = self.bans.read().await;
        let results: Vec<BanRecord> = bans
            .values()
            .filter(|ban| {
                ban.is_active && 
                ban.room_id.as_ref().map_or(false, |rid| rid == room_id)
            })
            .cloned()
            .collect();
        Ok(results)
    }
    
    async fn cleanup_expired_bans(&self) -> Result<usize> {
        let mut bans = self.bans.write().await;
        let now = Utc::now();
        let mut cleaned_count = 0;
        
        for ban in bans.values_mut() {
            if ban.is_active {
                if let Some(expiry) = ban.expires_at {
                    if now > expiry {
                        ban.is_active = false;
                        cleaned_count += 1;
                    }
                }
            }
        }
        
        Ok(cleaned_count)
    }
}

#[async_trait]
impl AnalyticsStorage for MemoryStorageProvider {
    async fn record_event(&self, event_type: &str, data: HashMap<String, String>) -> Result<()> {
        let mut analytics = self.analytics.write().await;
        let events = analytics.entry(event_type.to_string()).or_insert_with(Vec::new);
        events.push((Utc::now(), data));
        
        // Limit to last 1000 events per type to prevent memory bloat
        if events.len() > 1000 {
            events.drain(0..events.len() - 1000);
        }
        
        Ok(())
    }
    
    async fn get_event_count(
        &self,
        event_type: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<u64> {
        let analytics = self.analytics.read().await;
        if let Some(events) = analytics.get(event_type) {
            let count = events
                .iter()
                .filter(|(timestamp, _)| *timestamp >= start && *timestamp <= end)
                .count();
            Ok(count as u64)
        } else {
            Ok(0)
        }
    }
    
    async fn get_top_users(&self, limit: usize, _timeframe_hours: u64) -> Result<Vec<(String, u64)>> {
        let analytics = self.analytics.read().await;
        let mut user_counts: HashMap<String, u64> = HashMap::new();
        
        // Count message events per user
        if let Some(message_events) = analytics.get("message_sent") {
            for (_, data) in message_events {
                if let Some(user_id) = data.get("user_id") {
                    *user_counts.entry(user_id.clone()).or_insert(0) += 1;
                }
            }
        }
        
        let mut sorted_users: Vec<_> = user_counts.into_iter().collect();
        sorted_users.sort_by(|a, b| b.1.cmp(&a.1));
        sorted_users.truncate(limit);
        
        Ok(sorted_users)
    }
    
    async fn get_room_stats(&self, room_id: &str, _timeframe_hours: u64) -> Result<RoomStats> {
        let analytics = self.analytics.read().await;
        let mut message_count = 0;
        let mut unique_users = std::collections::HashSet::new();
        
        if let Some(message_events) = analytics.get("message_sent") {
            for (_, data) in message_events {
                if data.get("room_id").map_or(false, |rid| rid == room_id) {
                    message_count += 1;
                    if let Some(user_id) = data.get("user_id") {
                        unique_users.insert(user_id.clone());
                    }
                }
            }
        }
        
        let average_messages_per_user = if unique_users.is_empty() {
            0.0
        } else {
            message_count as f64 / unique_users.len() as f64
        };
        
        Ok(RoomStats {
            room_id: room_id.to_string(),
            message_count,
            unique_users: unique_users.len() as u64,
            peak_concurrent_users: unique_users.len() as u64, // Simplified
            average_messages_per_user,
        })
    }
    
    async fn get_server_stats(&self, _timeframe_hours: u64) -> Result<ServerStats> {
        let rooms = self.rooms.read().await;
        let users = self.users.read().await;
        let analytics = self.analytics.read().await;
        
        let mut total_messages = 0;
        if let Some(message_events) = analytics.get("message_sent") {
            total_messages = message_events.len() as u64;
        }
        
        let mut active_connections = 0;
        if let Some(connection_events) = analytics.get("connection_opened") {
            active_connections = connection_events.len() as u64;
        }
        
        Ok(ServerStats {
            total_messages,
            total_users: users.len() as u64,
            total_rooms: rooms.len() as u64,
            active_connections,
            peak_concurrent_connections: active_connections, // Simplified
            uptime_hours: 0.0, // Would need to track server start time
        })
    }
}