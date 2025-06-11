use serde::{Deserialize, Serialize};

/// User roles within a room
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UserRole {
    Owner,
    Admin,
    Moderator,
    Member,
    Guest,
}

impl UserRole {
    /// Returns the permissions associated with this role
    pub fn permissions(&self) -> Vec<Permission> {
        match self {
            UserRole::Owner => vec![
                Permission::ManageRoom,
                Permission::ManageRoles,
                Permission::KickUsers,
                Permission::BanUsers,
                Permission::MuteUsers,
                Permission::SendMessages,
                Permission::DeleteMessages,
                Permission::InviteUsers,
                Permission::CreateRooms,
            ],
            UserRole::Admin => vec![
                Permission::ManageRoles,
                Permission::KickUsers,
                Permission::BanUsers,
                Permission::MuteUsers,
                Permission::SendMessages,
                Permission::DeleteMessages,
                Permission::InviteUsers,
                Permission::CreateRooms,
            ],
            UserRole::Moderator => vec![
                Permission::KickUsers,
                Permission::MuteUsers,
                Permission::SendMessages,
                Permission::DeleteMessages,
            ],
            UserRole::Member => vec![Permission::SendMessages, Permission::InviteUsers],
            UserRole::Guest => vec![Permission::SendMessages],
        }
    }

    /// Check if this role has a specific permission
    pub fn has_permission(&self, permission: Permission) -> bool {
        self.permissions().contains(&permission)
    }
}

/// Permissions that can be granted to users
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    ManageRoom,     // Create, delete, configure rooms
    ManageRoles,    // Assign/remove roles
    KickUsers,      // Remove users from room
    BanUsers,       // Ban users from room
    MuteUsers,      // Mute users in room
    SendMessages,   // Send messages to room
    DeleteMessages, // Delete any message
    InviteUsers,    // Invite users to room
    CreateRooms,    // Create new rooms
}

/// Represents an authenticated user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique user identifier
    pub id: String,
    /// Username for display
    pub username: String,
    /// Email address (optional)
    pub email: Option<String>,
    /// Avatar URL (optional)
    pub avatar_url: Option<String>,
    /// Global role (for server-wide permissions)
    pub global_role: Option<UserRole>,
    /// Account creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last activity timestamp
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

impl User {
    /// Creates a new user with basic information
    pub fn new(id: String, username: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            id,
            username,
            email: None,
            avatar_url: None,
            global_role: None,
            created_at: now,
            last_seen: now,
        }
    }

    /// Creates a new user with email
    pub fn with_email(id: String, username: String, email: String) -> Self {
        let mut user = Self::new(id, username);
        user.email = Some(email);
        user
    }

    /// Check if user has global permission (room-specific permissions are managed by RoomManager)
    pub fn has_global_permission(&self, permission: Permission) -> bool {
        if let Some(global_role) = self.global_role {
            global_role.has_permission(permission)
        } else {
            false
        }
    }

    /// Update last seen timestamp
    pub fn touch(&mut self) {
        self.last_seen = chrono::Utc::now();
    }
}

// User persistence, password hashing, and OAuth provider support can be added in future versions
