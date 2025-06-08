// Unit tests that don't require external dependencies

#[cfg(test)]
mod auth_tests {
    use rusty_socks::auth::token::{Claims, TokenManager};
    use rusty_socks::auth::user::{Permission, User, UserRole};

    #[test]
    fn test_jwt_basic_functionality() {
        let token_manager = TokenManager::new("test-secret-key");

        // Create claims
        let claims = Claims::new(
            "user123".to_string(),
            "testuser".to_string(),
            Some("test@example.com".to_string()),
        );

        // Generate token
        let token = token_manager.generate_token(&claims).unwrap();
        assert!(!token.is_empty());

        // Validate token
        let validated = token_manager.validate_token(&token).unwrap();
        assert_eq!(validated.claims.sub, "user123");
        assert_eq!(validated.claims.username, "testuser");
    }

    #[test]
    fn test_user_roles_and_permissions() {
        // Test role permissions
        assert!(UserRole::Owner.has_permission(Permission::ManageRoom));
        assert!(!UserRole::Member.has_permission(Permission::ManageRoom));
        assert!(UserRole::Moderator.has_permission(Permission::KickUsers));
        assert!(!UserRole::Guest.has_permission(Permission::InviteUsers));

        // Test user creation with global role
        let mut user = User::new("user123".to_string(), "testuser".to_string());
        user.global_role = Some(UserRole::Admin);
        
        // Global admin role should have permissions
        assert_eq!(user.global_role, Some(UserRole::Admin));
        let admin_perms = UserRole::Admin.permissions();
        assert!(admin_perms.contains(&Permission::BanUsers));
        assert!(!admin_perms.contains(&Permission::ManageRoom));
    }
}

#[cfg(test)]
mod room_tests {
    use rusty_socks::auth::user::{Permission, UserRole};
    use rusty_socks::core::room::Room;

    #[test]
    fn test_room_basic_functionality() {
        let mut room = Room::new("Test Room".to_string());

        // Test room properties
        assert_eq!(room.name, "Test Room");
        assert!(!room.id.is_empty());
        assert_eq!(room.member_count(), 0);

        // Test member management
        assert!(room.add_member("user1".to_string()).is_ok());
        assert_eq!(room.member_count(), 1);
        assert!(room.has_member("user1"));

        // Test role assignment
        room.set_user_role("user1".to_string(), UserRole::Moderator);
        assert_eq!(room.get_user_role("user1"), Some(UserRole::Moderator));
        assert!(room.user_has_permission("user1", Permission::KickUsers));
    }

    #[test]
    fn test_room_capacity_and_bans() {
        let mut room = Room::with_limit("Small Room".to_string(), 2);

        // Fill to capacity
        assert!(room.add_member("user1".to_string()).is_ok());
        assert!(room.add_member("user2".to_string()).is_ok());

        // Should reject when full
        assert!(room.add_member("user3".to_string()).is_err());

        // Test ban system
        room.ban_user("user1".to_string(), None);
        assert!(room.is_banned("user1"));
        assert!(!room.has_member("user1"));

        // Banned user can't rejoin
        assert!(room.add_member("user1".to_string()).is_err());
    }
}

#[cfg(test)]
mod integration_tests {
    use rusty_socks::auth::token::{Claims, TokenManager};
    use rusty_socks::auth::user::User;
    use rusty_socks::core::room::RoomManager;

    #[tokio::test]
    async fn test_room_manager_workflow() {
        let manager = RoomManager::new();

        // Create room
        let room_id = manager
            .create_room("Test Room".to_string(), Some(10))
            .await
            .unwrap();

        // Join room
        assert!(manager
            .join_room("user1".to_string(), room_id.clone())
            .await
            .is_ok());

        // Check membership
        let members = manager.get_room_members(&room_id).await.unwrap();
        assert_eq!(members.len(), 1);
        assert!(members.contains(&"user1".to_string()));

        // Leave room
        assert!(manager.leave_room("user1", &room_id).await.is_ok());
        let members = manager.get_room_members(&room_id).await.unwrap();
        assert_eq!(members.len(), 0);
    }

    #[tokio::test]
    async fn test_auth_token_workflow() {
        let token_manager = TokenManager::new("test-secret");

        // Create user and generate token
        let user = User::new("test-id".to_string(), "testuser".to_string());
        let claims = Claims::new(user.id.clone(), user.username.clone(), None);
        let token = token_manager.generate_token(&claims).unwrap();

        // Validate token
        let validated_claims = token_manager.get_claims(&token).unwrap();
        assert_eq!(validated_claims.sub, user.id);
        assert_eq!(validated_claims.username, user.username);

        // Test user ID extraction
        let extracted_id = token_manager.validate_and_get_user_id(&token).unwrap();
        assert_eq!(extracted_id, user.id);
    }
}
