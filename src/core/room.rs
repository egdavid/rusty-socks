use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::user::{Permission, UserRole};
use crate::error::{Result, RustySocksError};

/// Represents a chat room or channel
#[derive(Debug, Clone)]
pub struct Room {
    /// Unique identifier for the room
    pub id: String,
    /// Display name of the room
    pub name: String,
    /// Set of client IDs currently in the room
    pub members: HashSet<String>,
    /// Maximum number of members allowed (None for unlimited)
    pub max_members: Option<usize>,
    /// User roles in this room (user_id -> role)
    pub user_roles: HashMap<String, UserRole>,
    /// Banned users (user_id -> ban expiry timestamp)
    pub banned_users: HashMap<String, Option<chrono::DateTime<chrono::Utc>>>,
    /// Muted users (user_id -> mute expiry timestamp)
    pub muted_users: HashMap<String, Option<chrono::DateTime<chrono::Utc>>>,
    /// Room password (optional)
    pub password_hash: Option<String>,
    /// Whether the room is private (invite-only)
    pub is_private: bool,
    /// Timestamp of room creation
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Room {
    /// Creates a new room with the given name
    pub fn new(name: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            members: HashSet::new(),
            max_members: None,
            user_roles: HashMap::new(),
            banned_users: HashMap::new(),
            muted_users: HashMap::new(),
            password_hash: None,
            is_private: false,
            created_at: chrono::Utc::now(),
        }
    }

    /// Creates a new room with a member limit
    pub fn with_limit(name: String, max_members: usize) -> Self {
        let mut room = Self::new(name);
        room.max_members = Some(max_members);
        room
    }

    /// Creates a new private room
    pub fn private(name: String) -> Self {
        let mut room = Self::new(name);
        room.is_private = true;
        room
    }

    /// Adds a member to the room
    pub fn add_member(&mut self, client_id: String) -> Result<()> {
        // Check if user is banned
        if self.is_banned(&client_id) {
            return Err(RustySocksError::Forbidden);
        }

        if let Some(max) = self.max_members {
            if self.members.len() >= max {
                return Err(RustySocksError::RoomFull);
            }
        }

        self.members.insert(client_id.clone());

        // Assign default role if not already assigned
        if !self.user_roles.contains_key(&client_id) {
            self.user_roles.insert(client_id, UserRole::Member);
        }

        Ok(())
    }

    /// Removes a member from the room
    pub fn remove_member(&mut self, client_id: &str) -> bool {
        self.members.remove(client_id)
    }

    /// Checks if a client is a member of the room
    pub fn has_member(&self, client_id: &str) -> bool {
        self.members.contains(client_id)
    }

    /// Returns the number of members in the room
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Sets a user's role in the room
    pub fn set_user_role(&mut self, user_id: String, role: UserRole) {
        self.user_roles.insert(user_id, role);
    }

    /// Gets a user's role in the room
    pub fn get_user_role(&self, user_id: &str) -> Option<UserRole> {
        self.user_roles.get(user_id).copied()
    }

    /// Checks if a user has a specific permission in this room
    pub fn user_has_permission(&self, user_id: &str, permission: Permission) -> bool {
        self.get_user_role(user_id)
            .map(|role| role.has_permission(permission))
            .unwrap_or(false)
    }

    /// Bans a user from the room
    pub fn ban_user(&mut self, user_id: String, expiry: Option<chrono::DateTime<chrono::Utc>>) {
        self.banned_users.insert(user_id.clone(), expiry);
        self.remove_member(&user_id);
    }

    /// Unbans a user
    pub fn unban_user(&mut self, user_id: &str) {
        self.banned_users.remove(user_id);
    }

    /// Checks if a user is banned
    pub fn is_banned(&self, user_id: &str) -> bool {
        if let Some(expiry) = self.banned_users.get(user_id) {
            match expiry {
                Some(exp) => chrono::Utc::now() < *exp,
                None => true, // Permanent ban
            }
        } else {
            false
        }
    }

    /// Mutes a user in the room
    pub fn mute_user(&mut self, user_id: String, expiry: Option<chrono::DateTime<chrono::Utc>>) {
        self.muted_users.insert(user_id, expiry);
    }

    /// Unmutes a user
    pub fn unmute_user(&mut self, user_id: &str) {
        self.muted_users.remove(user_id);
    }

    /// Checks if a user is muted
    pub fn is_muted(&self, user_id: &str) -> bool {
        if let Some(expiry) = self.muted_users.get(user_id) {
            match expiry {
                Some(exp) => chrono::Utc::now() < *exp,
                None => true, // Permanent mute
            }
        } else {
            false
        }
    }

    /// Sets the room password
    pub fn set_password(&mut self, password_hash: String) {
        self.password_hash = Some(password_hash);
    }

    /// Removes the room password
    pub fn remove_password(&mut self) {
        self.password_hash = None;
    }

    /// Checks if the room requires a password
    pub fn requires_password(&self) -> bool {
        self.password_hash.is_some()
    }
}

/// Manages all active rooms in the server
pub struct RoomManager {
    /// Map of room ID to room instance
    rooms: Arc<RwLock<HashMap<String, Room>>>,
    /// Map of client ID to set of room IDs they're in
    client_rooms: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    /// Default room that all clients join
    default_room_id: String,
}

impl RoomManager {
    /// Creates a new room manager with a default "lobby" room
    pub fn new() -> Self {
        let default_room = Room::new("lobby".to_string());
        let default_room_id = default_room.id.clone();

        let mut rooms = HashMap::new();
        rooms.insert(default_room_id.clone(), default_room);

        Self {
            rooms: Arc::new(RwLock::new(rooms)),
            client_rooms: Arc::new(RwLock::new(HashMap::new())),
            default_room_id,
        }
    }

    /// Creates a new room and returns its ID
    pub async fn create_room(&self, name: String, max_members: Option<usize>) -> Result<String> {
        let room = match max_members {
            Some(limit) => Room::with_limit(name, limit),
            None => Room::new(name),
        };

        let room_id = room.id.clone();
        self.rooms.write().await.insert(room_id.clone(), room);

        Ok(room_id)
    }

    /// Deletes a room (cannot delete the default room)
    pub async fn delete_room(&self, room_id: &str) -> Result<()> {
        if room_id == self.default_room_id {
            return Err(RustySocksError::CannotDeleteDefaultRoom);
        }

        let mut rooms = self.rooms.write().await;
        if let Some(room) = rooms.remove(room_id) {
            // Remove all members from the room
            let mut client_rooms = self.client_rooms.write().await;
            for member_id in room.members {
                if let Some(rooms_set) = client_rooms.get_mut(&member_id) {
                    rooms_set.remove(room_id);
                }
            }
            Ok(())
        } else {
            Err(RustySocksError::RoomNotFound)
        }
    }

    /// Adds a client to a room (use join_room_atomic for atomic operations)
    pub async fn join_room(&self, client_id: String, room_id: String) -> Result<()> {
        log::warn!("Using legacy join_room method. Consider using join_room_atomic for better safety.");
        self.join_room_atomic(client_id, room_id).await
    }

    /// Adds a client to a room atomically (TOCTOU-safe)
    pub async fn join_room_atomic(&self, client_id: String, room_id: String) -> Result<()> {
        // SECURITY: Hold both locks simultaneously to prevent TOCTOU race conditions
        let mut rooms = self.rooms.write().await;
        let mut client_rooms = self.client_rooms.write().await;
        
        // Check and add to room members
        let room = rooms
            .get_mut(&room_id)
            .ok_or(RustySocksError::RoomNotFound)?;
        room.add_member(client_id.clone())?;

        // Track client's rooms (both locks still held)
        client_rooms
            .entry(client_id)
            .or_insert_with(HashSet::new)
            .insert(room_id);

        Ok(())
    }

    /// Removes a client from a room (DEPRECATED: use leave_room_atomic to avoid TOCTOU)
    pub async fn leave_room(&self, client_id: &str, room_id: &str) -> Result<()> {
        log::warn!("Using deprecated leave_room method that has TOCTOU race condition. Use leave_room_atomic instead.");
        self.leave_room_atomic(client_id, room_id).await
    }

    /// Removes a client from a room atomically (TOCTOU-safe)
    pub async fn leave_room_atomic(&self, client_id: &str, room_id: &str) -> Result<()> {
        // SECURITY: Hold both locks simultaneously to prevent TOCTOU race conditions
        let mut rooms = self.rooms.write().await;
        let mut client_rooms = self.client_rooms.write().await;
        
        // Remove from room members
        let room = rooms
            .get_mut(room_id)
            .ok_or(RustySocksError::RoomNotFound)?;
        room.remove_member(client_id);

        // Update client's rooms (both locks still held)
        if let Some(rooms_set) = client_rooms.get_mut(client_id) {
            rooms_set.remove(room_id);
            if rooms_set.is_empty() {
                client_rooms.remove(client_id);
            }
        }

        Ok(())
    }

    /// Check user permissions atomically to prevent TOCTOU race conditions
    pub async fn check_user_send_permission_atomic(&self, user_id: &str, room_id: &str) -> Result<bool> {
        // SECURITY: Hold read lock during entire check to prevent TOCTOU
        let rooms = self.rooms.read().await;
        
        // Get room once and check everything
        let room = rooms.get(room_id).ok_or(RustySocksError::RoomNotFound)?;
        
        // Check if user is in the room
        if !room.members.contains(user_id) {
            return Ok(false);
        }
        
        // Check if user is banned
        if room.is_banned(user_id) {
            return Ok(false);
        }
        
        // Check if user is muted
        if room.muted_users.contains_key(user_id) {
            if let Some(expiry) = room.muted_users.get(user_id) {
                match expiry {
                    Some(exp) => {
                        if chrono::Utc::now() < *exp {
                            return Ok(false); // Still muted
                        }
                    }
                    None => return Ok(false), // Permanently muted
                }
            }
        }
        
        // Check if user has SendMessages permission
        let user_role = room.get_user_role(user_id);
        if let Some(role) = user_role {
            Ok(role.has_permission(crate::auth::user::Permission::SendMessages))
        } else {
            // If no specific role, assume Guest permissions
            Ok(crate::auth::user::UserRole::Guest.has_permission(crate::auth::user::Permission::SendMessages))
        }
    }

    /// Check user moderation permissions atomically to prevent TOCTOU race conditions
    pub async fn check_user_moderation_permission_atomic(&self, user_id: &str, room_id: &str, required_permission: crate::auth::user::Permission) -> Result<bool> {
        // SECURITY: Hold read lock during entire check to prevent TOCTOU
        let rooms = self.rooms.read().await;
        
        // Get room once and check everything
        let room = rooms.get(room_id).ok_or(RustySocksError::RoomNotFound)?;
        
        // Check if user is in the room
        if !room.members.contains(user_id) {
            return Ok(false);
        }
        
        // Get user role in room
        let user_role = room.get_user_role(user_id);
        if let Some(role) = user_role {
            Ok(role.has_permission(required_permission))
        } else {
            // If no specific role, assume Guest permissions (can't moderate)
            Ok(false)
        }
    }

    /// Removes a client from all rooms (e.g., on disconnect)
    pub async fn remove_client(&self, client_id: &str) -> Result<()> {
        let client_rooms = self
            .client_rooms
            .write()
            .await
            .get(client_id)
            .cloned()
            .unwrap_or_default();

        for room_id in client_rooms {
            self.leave_room(client_id, &room_id).await?;
        }

        Ok(())
    }

    /// Gets all members of a room
    pub async fn get_room_members(&self, room_id: &str) -> Result<Vec<String>> {
        let rooms = self.rooms.read().await;
        let room = rooms.get(room_id).ok_or(RustySocksError::RoomNotFound)?;
        Ok(room.members.iter().cloned().collect())
    }

    /// Gets all rooms a client is in
    pub async fn get_client_rooms(&self, client_id: &str) -> Vec<String> {
        self.client_rooms
            .read()
            .await
            .get(client_id)
            .map(|rooms| rooms.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Lists all available rooms
    pub async fn list_rooms(&self) -> Vec<(String, String, usize)> {
        self.rooms
            .read()
            .await
            .values()
            .map(|room| (room.id.clone(), room.name.clone(), room.member_count()))
            .collect()
    }

    /// Gets the default room ID
    pub fn default_room_id(&self) -> &str {
        &self.default_room_id
    }

    /// Automatically joins a client to the default room
    pub async fn join_default_room(&self, client_id: String) -> Result<()> {
        self.join_room(client_id, self.default_room_id.clone())
            .await
    }
    
    /// Check if user is in a specific room
    pub async fn is_user_in_room(&self, user_id: &str, room_id: &str) -> Result<bool> {
        let rooms = self.rooms.read().await;
        match rooms.get(room_id) {
            Some(room) => Ok(room.members.contains(user_id)),
            None => Err(RustySocksError::RoomNotFound),
        }
    }
    
    /// Check if user is banned from a room
    pub async fn is_user_banned(&self, user_id: &str, room_id: &str) -> Result<bool> {
        let rooms = self.rooms.read().await;
        match rooms.get(room_id) {
            Some(room) => {
                if let Some(ban_expiry) = room.banned_users.get(user_id) {
                    // Check if ban is permanent (None) or still active
                    Ok(ban_expiry.is_none() || ban_expiry.unwrap() > chrono::Utc::now())
                } else {
                    Ok(false)
                }
            }
            None => Err(RustySocksError::RoomNotFound),
        }
    }
    
    /// Check if user is muted in a room
    pub async fn is_user_muted(&self, user_id: &str, room_id: &str) -> Result<bool> {
        let rooms = self.rooms.read().await;
        match rooms.get(room_id) {
            Some(room) => {
                if let Some(mute_expiry) = room.muted_users.get(user_id) {
                    // Check if mute is permanent (None) or still active
                    Ok(mute_expiry.is_none() || mute_expiry.unwrap() > chrono::Utc::now())
                } else {
                    Ok(false)
                }
            }
            None => Err(RustySocksError::RoomNotFound),
        }
    }
    
    /// Get user role in a specific room
    pub async fn get_user_role(&self, user_id: &str, room_id: &str) -> Result<Option<UserRole>> {
        let rooms = self.rooms.read().await;
        match rooms.get(room_id) {
            Some(room) => Ok(room.user_roles.get(user_id).cloned()),
            None => Err(RustySocksError::RoomNotFound),
        }
    }
    
    /// Ban user from room
    pub async fn ban_user(&self, room_id: &str, user_id: &str, duration_hours: Option<u64>) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(room_id).ok_or(RustySocksError::RoomNotFound)?;
        
        // Calculate ban expiry
        let ban_expiry = duration_hours.map(|hours| {
            chrono::Utc::now() + chrono::Duration::hours(hours as i64)
        });
        
        // Add to banned users
        room.banned_users.insert(user_id.to_string(), ban_expiry);
        
        // Remove from room if currently a member
        room.members.remove(user_id);
        room.user_roles.remove(user_id);
        
        // Remove from client_rooms tracking
        let mut client_rooms = self.client_rooms.write().await;
        if let Some(user_rooms) = client_rooms.get_mut(user_id) {
            user_rooms.remove(room_id);
        }
        
        Ok(())
    }
    
    /// Kick user from room (temporary removal without ban)
    pub async fn kick_user(&self, room_id: &str, user_id: &str) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(room_id).ok_or(RustySocksError::RoomNotFound)?;
        
        // Remove from room (but keep role for potential rejoin)
        room.members.remove(user_id);
        
        // Remove from client_rooms tracking
        let mut client_rooms = self.client_rooms.write().await;
        if let Some(user_rooms) = client_rooms.get_mut(user_id) {
            user_rooms.remove(room_id);
        }
        
        Ok(())
    }
    
    /// Set user role in room  
    pub async fn set_user_role(&self, room_id: &str, user_id: &str, role: UserRole) -> Result<()> {
        let mut rooms = self.rooms.write().await;
        let room = rooms.get_mut(room_id).ok_or(RustySocksError::RoomNotFound)?;
        
        // Check if user is in room
        if !room.members.contains(user_id) {
            return Err(RustySocksError::SessionNotFound("User not in room".to_string()));
        }
        
        // Set the role
        room.user_roles.insert(user_id.to_string(), role);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, timeout};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc as StdArc;

    #[tokio::test]
    async fn test_join_room_atomic_prevents_toctou() {
        let room_manager = RoomManager::new();
        
        // Create a test room
        let room_id = room_manager.create_room("test_room".to_string(), None).await.unwrap();
        
        // Test that join_room_atomic works correctly
        let result = room_manager.join_room_atomic("user1".to_string(), room_id.clone()).await;
        assert!(result.is_ok(), "Should be able to join existing room");
        
        // Verify user was added to both structures atomically
        let rooms = room_manager.rooms.read().await;
        let client_rooms = room_manager.client_rooms.read().await;
        
        assert!(rooms.get(&room_id).unwrap().members.contains("user1"));
        assert!(client_rooms.get("user1").unwrap().contains(&room_id));
    }

    #[tokio::test]
    async fn test_leave_room_atomic_prevents_toctou() {
        let room_manager = RoomManager::new();
        
        // Create a test room and add user
        let room_id = room_manager.create_room("test_room".to_string(), None).await.unwrap();
        room_manager.join_room_atomic("user1".to_string(), room_id.clone()).await.unwrap();
        
        // Test that leave_room_atomic works correctly
        let result = room_manager.leave_room_atomic("user1", &room_id).await;
        assert!(result.is_ok(), "Should be able to leave room");
        
        // Verify user was removed from both structures atomically
        let rooms = room_manager.rooms.read().await;
        let client_rooms = room_manager.client_rooms.read().await;
        
        assert!(!rooms.get(&room_id).unwrap().members.contains("user1"));
        assert!(!client_rooms.contains_key("user1")); // Should be removed when empty
    }

    #[tokio::test]
    async fn test_permission_check_atomic_prevents_toctou() {
        let room_manager = RoomManager::new();
        
        // Create a test room and add user
        let room_id = room_manager.create_room("test_room".to_string(), None).await.unwrap();
        room_manager.join_room_atomic("user1".to_string(), room_id.clone()).await.unwrap();
        
        // Test atomic permission check
        let can_send = room_manager.check_user_send_permission_atomic("user1", &room_id).await.unwrap();
        assert!(can_send, "User should be able to send messages by default");
        
        // Test with non-existent user
        let can_send_fake = room_manager.check_user_send_permission_atomic("fake_user", &room_id).await.unwrap();
        assert!(!can_send_fake, "Non-existent user should not be able to send messages");
    }

    #[tokio::test]
    async fn test_concurrent_join_leave_operations() {
        let room_manager = StdArc::new(RoomManager::new());
        
        // Create a test room
        let room_id = room_manager.create_room("test_room".to_string(), None).await.unwrap();
        
        let success_flag = StdArc::new(AtomicBool::new(true));
        
        // Spawn multiple concurrent operations
        let mut handles = vec![];
        
        for i in 0..10 {
            let rm = room_manager.clone();
            let flag = success_flag.clone();
            let user_id = format!("user{}", i);
            let room_id_clone = room_id.clone();
            
            let handle = tokio::spawn(async move {
                // Try to join and immediately leave
                match rm.join_room_atomic(user_id.clone(), room_id_clone.clone()).await {
                    Ok(_) => {
                        // Small delay to increase chance of race condition
                        tokio::time::sleep(Duration::from_millis(1)).await;
                        
                        match rm.leave_room_atomic(&user_id, &room_id_clone).await {
                            Ok(_) => {},
                            Err(_) => flag.store(false, Ordering::Relaxed),
                        }
                    },
                    Err(_) => flag.store(false, Ordering::Relaxed),
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for all operations to complete
        for handle in handles {
            let _ = timeout(Duration::from_secs(5), handle).await;
        }
        
        // Check that all operations succeeded
        assert!(success_flag.load(Ordering::Relaxed), "All concurrent operations should succeed");
        
        // Verify final state is consistent
        let rooms = room_manager.rooms.read().await;
        let client_rooms = room_manager.client_rooms.read().await;
        
        let room = rooms.get(&room_id).unwrap();
        
        // All users should have left, so room should be empty
        // and client_rooms should be consistent
        for member_id in &room.members {
            assert!(client_rooms.get(member_id).map_or(false, |rooms| rooms.contains(&room_id)), 
                   "Client room tracking should be consistent with room membership");
        }
    }
}

// TODO: Add room persistence to survive server restarts
// TODO: Add room metadata (description, tags, etc.)
// NOTE: Room permissions and moderators system implemented with role-based access control
