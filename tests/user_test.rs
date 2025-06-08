use rusty_socks::auth::user::{Permission, User, UserRole};

#[test]
fn test_user_creation() {
    let user = User::new("user123".to_string(), "testuser".to_string());
    assert_eq!(user.id, "user123");
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, None);
    assert_eq!(user.avatar_url, None);
    assert_eq!(user.global_role, None);
}

#[test]
fn test_user_with_email() {
    let user = User::with_email(
        "user123".to_string(),
        "testuser".to_string(),
        "test@example.com".to_string(),
    );
    assert_eq!(user.email, Some("test@example.com".to_string()));
}

#[test]
fn test_role_permissions() {
    // Owner has all permissions
    let owner_perms = UserRole::Owner.permissions();
    assert!(owner_perms.contains(&Permission::ManageRoom));
    assert!(owner_perms.contains(&Permission::ManageRoles));
    assert!(owner_perms.contains(&Permission::BanUsers));
    assert!(owner_perms.contains(&Permission::KickUsers));
    assert!(owner_perms.contains(&Permission::SendMessages));

    // Admin has most permissions but not ManageRoom
    let admin_perms = UserRole::Admin.permissions();
    assert!(!admin_perms.contains(&Permission::ManageRoom));
    assert!(admin_perms.contains(&Permission::ManageRoles));
    assert!(admin_perms.contains(&Permission::BanUsers));

    // Moderator has limited permissions
    let mod_perms = UserRole::Moderator.permissions();
    assert!(!mod_perms.contains(&Permission::ManageRoom));
    assert!(!mod_perms.contains(&Permission::ManageRoles));
    assert!(!mod_perms.contains(&Permission::BanUsers));
    assert!(mod_perms.contains(&Permission::KickUsers));
    assert!(mod_perms.contains(&Permission::DeleteMessages));

    // Member has basic permissions
    let member_perms = UserRole::Member.permissions();
    assert!(member_perms.contains(&Permission::SendMessages));
    assert!(member_perms.contains(&Permission::InviteUsers));
    assert!(!member_perms.contains(&Permission::DeleteMessages));

    // Guest has minimal permissions
    let guest_perms = UserRole::Guest.permissions();
    assert!(guest_perms.contains(&Permission::SendMessages));
    assert!(!guest_perms.contains(&Permission::InviteUsers));
}

#[test]
fn test_user_global_role() {
    let mut user = User::new("user123".to_string(), "testuser".to_string());
    
    // Initially no global role
    assert_eq!(user.global_role, None);
    
    // Set global role
    user.global_role = Some(UserRole::Admin);
    assert_eq!(user.global_role, Some(UserRole::Admin));
}

#[test]
fn test_user_touch() {
    let mut user = User::new("user123".to_string(), "testuser".to_string());
    let initial_last_seen = user.last_seen;

    // Wait a bit and touch
    std::thread::sleep(std::time::Duration::from_millis(10));
    user.touch();

    assert!(user.last_seen > initial_last_seen);
}

#[test]
fn test_role_has_permission() {
    assert!(UserRole::Owner.has_permission(Permission::ManageRoom));
    assert!(!UserRole::Member.has_permission(Permission::ManageRoom));
    assert!(UserRole::Moderator.has_permission(Permission::KickUsers));
    assert!(!UserRole::Guest.has_permission(Permission::InviteUsers));
}