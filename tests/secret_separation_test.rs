//! Tests for JWT and CSRF secret separation

use rusty_socks::config::ServerConfig;
use std::env;

#[test]
fn test_separate_secrets_validation() {
    // Save original environment
    let original_jwt = env::var("RUSTY_SOCKS_JWT_SECRET").ok();
    let original_csrf = env::var("RUSTY_SOCKS_CSRF_SECRET").ok();
    
    // Test that different secrets are accepted (avoid "secret" keyword)
    env::set_var("RUSTY_SOCKS_JWT_SECRET", "secure_jwt_key_with_32_characters_minimum_abc123");
    env::set_var("RUSTY_SOCKS_CSRF_SECRET", "different_csrf_key_32_chars_long_def456");
    
    let config = ServerConfig::from_env();
    if let Err(ref e) = config {
        eprintln!("Config error: {}", e);
    }
    assert!(config.is_ok(), "Should accept different secrets: {:?}", config.err());
    
    let config = config.unwrap();
    assert_ne!(config.jwt_secret, config.csrf_secret, "Secrets should be different");
    
    // Restore original environment
    match original_jwt {
        Some(val) => env::set_var("RUSTY_SOCKS_JWT_SECRET", val),
        None => env::remove_var("RUSTY_SOCKS_JWT_SECRET"),
    }
    match original_csrf {
        Some(val) => env::set_var("RUSTY_SOCKS_CSRF_SECRET", val),
        None => env::remove_var("RUSTY_SOCKS_CSRF_SECRET"),
    }
}

#[test]
fn test_same_secrets_rejected() {
    // Test that same secrets are rejected
    let same_key = "same_key_used_for_both_purposes_32_chars_xyz";
    env::set_var("RUSTY_SOCKS_JWT_SECRET", same_key);
    env::set_var("RUSTY_SOCKS_CSRF_SECRET", same_key);
    
    let config = ServerConfig::from_env();
    assert!(config.is_err(), "Should reject identical secrets");
    
    let error = config.unwrap_err();
    assert!(error.to_string().contains("must be different"), 
           "Error should mention secrets must be different");
    
    // Clean up
    env::remove_var("RUSTY_SOCKS_JWT_SECRET");
    env::remove_var("RUSTY_SOCKS_CSRF_SECRET");
}

#[test]
fn test_insecure_patterns_rejected() {
    // Test that insecure patterns are rejected for both secrets
    let insecure_patterns = [
        "INSECURE-DEFAULT-FOR-TESTING-ONLY",
        "INSECURE-CSRF-DEFAULT-FOR-TESTING-ONLY",
        "your-secret-key",
        "test-secret",
        "password"
    ];
    
    for pattern in &insecure_patterns {
        env::set_var("RUSTY_SOCKS_JWT_SECRET", format!("{}_jwt_key_32chars", pattern));
        env::set_var("RUSTY_SOCKS_CSRF_SECRET", format!("{}_csrf_key_32chars", pattern));
        
        let config = ServerConfig::from_env();
        assert!(config.is_err(), "Should reject insecure pattern: {}", pattern);
        
        env::remove_var("RUSTY_SOCKS_JWT_SECRET");
        env::remove_var("RUSTY_SOCKS_CSRF_SECRET");
    }
}

#[test]
fn test_short_secrets_rejected() {
    // Test that secrets shorter than 32 characters are rejected
    env::set_var("RUSTY_SOCKS_JWT_SECRET", "short"); // Only 5 characters
    env::set_var("RUSTY_SOCKS_CSRF_SECRET", "different_but_secure_32_character_long_key");
    
    let config = ServerConfig::from_env();
    assert!(config.is_err(), "Should reject short JWT secret");
    
    env::set_var("RUSTY_SOCKS_JWT_SECRET", "secure_jwt_key_with_32_characters_minimum_abc");
    env::set_var("RUSTY_SOCKS_CSRF_SECRET", "short"); // Only 5 characters
    
    let config = ServerConfig::from_env();
    assert!(config.is_err(), "Should reject short CSRF secret");
    
    // Clean up
    env::remove_var("RUSTY_SOCKS_JWT_SECRET");
    env::remove_var("RUSTY_SOCKS_CSRF_SECRET");
}

#[test]
fn test_missing_csrf_secret_error() {
    // Test that missing CSRF secret is reported with helpful error
    env::set_var("RUSTY_SOCKS_JWT_SECRET", "secure_jwt_key_with_32_characters_minimum_abc");
    env::remove_var("RUSTY_SOCKS_CSRF_SECRET");
    env::remove_var("CSRF_SECRET");
    
    let config = ServerConfig::from_env();
    assert!(config.is_err(), "Should reject missing CSRF secret");
    
    let error = config.unwrap_err();
    assert!(error.to_string().contains("CSRF_SECRET"), 
           "Error should mention CSRF_SECRET is required");
    assert!(error.to_string().contains("different from JWT"), 
           "Error should mention it must be different from JWT");
    
    // Clean up
    env::remove_var("RUSTY_SOCKS_JWT_SECRET");
}

#[tokio::test]
async fn test_csrf_protection_uses_separate_secret() {
    use rusty_socks::security::CSRFProtection;
    
    let _jwt_key = "secure_jwt_key_with_32_characters_minimum_abc";
    let csrf_key = "different_csrf_key_32_chars_long_xyz789";
    
    // Create CSRF protection with the dedicated secret
    let csrf_protection = CSRFProtection::new(
        vec![],
        false,
        csrf_key.to_string(),
    );
    
    // Generate a token and verify it works
    let session_id = "test_session";
    let token = csrf_protection.generate_csrf_token(session_id);
    
    let validation_result = csrf_protection.validate_csrf_token(&token, session_id).await;
    assert!(matches!(validation_result, rusty_socks::security::CSRFValidationResult::Valid),
           "CSRF token validation should work with dedicated secret");
}