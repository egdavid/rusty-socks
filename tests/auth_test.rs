use rusty_socks::auth::token::{Claims, TokenManager};
use rusty_socks::handlers::auth::{authenticate_connection, extract_token_from_url};

#[test]
fn test_jwt_token_creation_and_validation() {
    let token_manager = TokenManager::new("test-secret-key");

    // Create claims
    let claims = Claims::new(
        "user123".to_string(),
        "testuser".to_string(),
        Some("test@example.com".to_string()),
    ).unwrap();

    // Generate token
    let token = token_manager.generate_token(&claims).unwrap();
    assert!(!token.is_empty());

    // Validate token (using sync version for tests)
    let validated = token_manager.validate_token_sync(&token).unwrap();
    assert_eq!(validated.claims.sub, "user123");
    assert_eq!(validated.claims.username, Some("testuser".to_string()));
    assert_eq!(validated.claims.email, Some("test@example.com".to_string()));
}

#[test]
fn test_invalid_token_validation() {
    let token_manager = TokenManager::new("test-secret-key");

    // Try to validate invalid token (using sync version for tests)
    let result = token_manager.validate_token_sync("invalid.token.here");
    assert!(result.is_err());
}

#[test]
fn test_expired_token() {
    let _token_manager = TokenManager::new("test-secret-key");

    // Create claims with 0 hours expiration
    let mut claims =
        Claims::with_expiration("user123".to_string(), "testuser".to_string(), None, 0).unwrap();

    // Manually set expiration to past
    claims.exp = claims.iat - 3600; // 1 hour ago

    assert!(claims.is_expired());
}

#[test]
fn test_extract_token_from_url_security_disabled() {
    // Test that URL token extraction is now completely disabled for security
    let uri = warp::hyper::Uri::from_static("/ws?token=abc123&other=value");
    let token = extract_token_from_url(&uri);
    assert_eq!(token, None); // Should now return None for security

    // Test without token
    let uri = warp::hyper::Uri::from_static("/ws?other=value&another=test");
    let token = extract_token_from_url(&uri);
    assert_eq!(token, None);

    // Test empty query
    let uri = warp::hyper::Uri::from_static("/ws");
    let token = extract_token_from_url(&uri);
    assert_eq!(token, None);
}

#[tokio::test]
async fn test_authenticate_connection_with_valid_token() {
    let token_manager = TokenManager::new("test-secret-key");

    // Create and sign a token
    let claims = Claims::new("user123".to_string(), "testuser".to_string(), None).unwrap();
    let token = token_manager.generate_token(&claims).unwrap();

    // Authenticate
    let result = authenticate_connection(Some(token), &token_manager, true).await;
    assert!(result.is_ok());

    let user_opt = result.unwrap();
    assert!(user_opt.is_some());

    let user = user_opt.unwrap();
    assert_eq!(user.id, "user123");
    assert_eq!(user.username, "testuser");
}

#[tokio::test]
async fn test_authenticate_connection_without_token() {
    let token_manager = TokenManager::new("test-secret-key");

    // Authenticate without token (anonymous)
    let result = authenticate_connection(None, &token_manager, true).await;
    assert!(result.is_ok());

    let user_opt = result.unwrap();
    assert!(user_opt.is_none()); // Anonymous connection
}

#[tokio::test]
async fn test_authenticate_connection_with_invalid_token() {
    let token_manager = TokenManager::new("test-secret-key");

    // Authenticate with invalid token
    let result = authenticate_connection(Some("invalid.token".to_string()), &token_manager, true).await;
    assert!(result.is_err());
}
