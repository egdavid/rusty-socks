//! Message types for room-based communication

use serde::{Deserialize, Serialize};

/// Client-to-server message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Join a room
    #[serde(rename = "join_room")]
    JoinRoom {
        room_id: String,
        password: Option<String>,
    },

    /// Leave a room
    #[serde(rename = "leave_room")]
    LeaveRoom { room_id: String },

    /// Send message to a room
    #[serde(rename = "room_message")]
    RoomMessage { room_id: String, content: String },

    /// Send private message to a user
    #[serde(rename = "private_message")]
    PrivateMessage {
        target_user_id: String,
        content: String,
    },

    /// Create a new room
    #[serde(rename = "create_room")]
    CreateRoom {
        name: String,
        is_private: Option<bool>,
        max_members: Option<usize>,
        password: Option<String>,
    },

    /// List available rooms
    #[serde(rename = "list_rooms")]
    ListRooms,

    /// Get room members
    #[serde(rename = "get_room_members")]
    GetRoomMembers { room_id: String },

    /// Set user role in room (requires permissions)
    #[serde(rename = "set_user_role")]
    SetUserRole {
        room_id: String,
        user_id: String,
        role: String, // UserRole as string
    },

    /// Ban user from room (requires permissions)
    #[serde(rename = "ban_user")]
    BanUser {
        room_id: String,
        user_id: String,
        duration_hours: Option<u64>,
    },

    /// Kick user from room (requires permissions)
    #[serde(rename = "kick_user")]
    KickUser { room_id: String, user_id: String },
}

/// Server-to-client message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Connection established
    #[serde(rename = "connected")]
    Connected {
        client_id: String,
        authenticated: bool,
        username: Option<String>,
    },

    /// Room message from another user
    #[serde(rename = "room_message")]
    RoomMessage {
        room_id: String,
        sender_id: String,
        sender_username: String,
        content: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Private message from another user
    #[serde(rename = "private_message")]
    PrivateMessage {
        sender_id: String,
        sender_username: String,
        content: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// System message (join/leave notifications, etc.)
    #[serde(rename = "system_message")]
    SystemMessage {
        room_id: Option<String>,
        content: String,
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// User joined room
    #[serde(rename = "user_joined")]
    UserJoined {
        room_id: String,
        user_id: String,
        username: String,
    },

    /// User left room
    #[serde(rename = "user_left")]
    UserLeft {
        room_id: String,
        user_id: String,
        username: String,
    },

    /// Room list response
    #[serde(rename = "room_list")]
    RoomList { rooms: Vec<RoomInfo> },

    /// Room members response
    #[serde(rename = "room_members")]
    RoomMembers {
        room_id: String,
        members: Vec<UserInfo>,
    },

    /// Error message
    #[serde(rename = "error")]
    Error { code: String, message: String },

    /// Success response
    #[serde(rename = "success")]
    Success {
        message: String,
        data: Option<serde_json::Value>,
    },
}

/// Room information for listings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomInfo {
    pub id: String,
    pub name: String,
    pub member_count: usize,
    pub max_members: Option<usize>,
    pub is_private: bool,
    pub requires_password: bool,
}

/// User information for room member listings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub role: Option<String>,
    pub is_online: bool,
}
