use rusty_socks::auth::user::{Permission, UserRole};
use rusty_socks::core::room::{Room, RoomManager};

#[test]
fn test_room_creation() {
    let room = Room::new("Test Room".to_string());
    assert_eq!(room.name, "Test Room");
    assert!(!room.id.is_empty());
    assert_eq!(room.member_count(), 0);
    assert!(!room.is_private);
    assert!(!room.requires_password());
}

#[test]
fn test_room_with_limit() {
    let room = Room::with_limit("Limited Room".to_string(), 10);
    assert_eq!(room.max_members, Some(10));
}

#[test]
fn test_private_room() {
    let room = Room::private("Private Room".to_string());
    assert!(room.is_private);
}

#[test]
fn test_room_member_management() {
    let mut room = Room::new("Test Room".to_string());

    // Add member
    assert!(room.add_member("user1".to_string()).is_ok());
    assert_eq!(room.member_count(), 1);
    assert!(room.has_member("user1"));

    // Check default role
    assert_eq!(room.get_user_role("user1"), Some(UserRole::Member));

    // Remove member
    assert!(room.remove_member("user1"));
    assert_eq!(room.member_count(), 0);
    assert!(!room.has_member("user1"));
}

#[test]
fn test_room_capacity_limit() {
    let mut room = Room::with_limit("Small Room".to_string(), 2);

    // Add members up to limit
    assert!(room.add_member("user1".to_string()).is_ok());
    assert!(room.add_member("user2".to_string()).is_ok());

    // Try to exceed limit
    let result = room.add_member("user3".to_string());
    assert!(result.is_err());
    assert_eq!(room.member_count(), 2);
}

#[test]
fn test_room_roles_and_permissions() {
    let mut room = Room::new("Test Room".to_string());

    room.add_member("owner".to_string()).unwrap();
    room.add_member("mod".to_string()).unwrap();

    // Set roles
    room.set_user_role("owner".to_string(), UserRole::Owner);
    room.set_user_role("mod".to_string(), UserRole::Moderator);

    // Check permissions
    assert!(room.user_has_permission("owner", Permission::ManageRoom));
    assert!(room.user_has_permission("owner", Permission::BanUsers));
    assert!(room.user_has_permission("mod", Permission::KickUsers));
    assert!(!room.user_has_permission("mod", Permission::ManageRoom));
}

#[test]
fn test_room_ban_system() {
    let mut room = Room::new("Test Room".to_string());

    // Add and ban user
    room.add_member("user1".to_string()).unwrap();
    room.ban_user("user1".to_string(), None); // Permanent ban

    // Check ban
    assert!(room.is_banned("user1"));
    assert!(!room.has_member("user1")); // User removed from room

    // Try to re-add banned user
    let result = room.add_member("user1".to_string());
    assert!(result.is_err());

    // Unban
    room.unban_user("user1");
    assert!(!room.is_banned("user1"));

    // Now can add again
    assert!(room.add_member("user1".to_string()).is_ok());
}

#[test]
fn test_room_mute_system() {
    let mut room = Room::new("Test Room".to_string());

    room.add_member("user1".to_string()).unwrap();

    // Mute user
    room.mute_user("user1".to_string(), None); // Permanent mute
    assert!(room.is_muted("user1"));
    assert!(room.has_member("user1")); // Still in room

    // Unmute
    room.unmute_user("user1");
    assert!(!room.is_muted("user1"));
}

#[test]
fn test_room_password() {
    let mut room = Room::new("Test Room".to_string());

    // Set password
    room.set_password("hashed_password_here".to_string());
    assert!(room.requires_password());

    // Remove password
    room.remove_password();
    assert!(!room.requires_password());
}

#[tokio::test]
async fn test_room_manager() {
    let manager = RoomManager::new();

    // Default room exists
    let default_id = manager.default_room_id();
    assert!(!default_id.is_empty());

    // Create room
    let room_id = manager
        .create_room("Custom Room".to_string(), None)
        .await
        .unwrap();
    assert!(!room_id.is_empty());

    // List rooms
    let rooms = manager.list_rooms().await;
    assert_eq!(rooms.len(), 2); // Default + Custom

    // Join room
    assert!(manager
        .join_room("user1".to_string(), room_id.clone())
        .await
        .is_ok());

    // Check members
    let members = manager.get_room_members(&room_id).await.unwrap();
    assert_eq!(members.len(), 1);
    assert!(members.contains(&"user1".to_string()));

    // Check client rooms
    let client_rooms = manager.get_client_rooms("user1").await;
    assert_eq!(client_rooms.len(), 1);
    assert!(client_rooms.contains(&room_id));

    // Leave room
    assert!(manager.leave_room("user1", &room_id).await.is_ok());
    let members = manager.get_room_members(&room_id).await.unwrap();
    assert_eq!(members.len(), 0);
}

#[tokio::test]
async fn test_room_manager_auto_join_default() {
    let manager = RoomManager::new();

    // Auto join default room
    assert!(manager.join_default_room("user1".to_string()).await.is_ok());

    // Check if in default room
    let default_members = manager
        .get_room_members(manager.default_room_id())
        .await
        .unwrap();
    assert!(default_members.contains(&"user1".to_string()));
}

#[tokio::test]
async fn test_room_manager_remove_client() {
    let manager = RoomManager::new();

    // Join multiple rooms
    let room1 = manager
        .create_room("Room1".to_string(), None)
        .await
        .unwrap();
    let room2 = manager
        .create_room("Room2".to_string(), None)
        .await
        .unwrap();

    manager
        .join_room("user1".to_string(), room1.clone())
        .await
        .unwrap();
    manager
        .join_room("user1".to_string(), room2.clone())
        .await
        .unwrap();

    // Remove client from all rooms
    assert!(manager.remove_client("user1").await.is_ok());

    // Check removed from all rooms
    let rooms = manager.get_client_rooms("user1").await;
    assert_eq!(rooms.len(), 0);
}

#[tokio::test]
async fn test_room_manager_delete_protection() {
    let manager = RoomManager::new();

    // Try to delete default room
    let result = manager.delete_room(manager.default_room_id()).await;
    assert!(result.is_err());
}
