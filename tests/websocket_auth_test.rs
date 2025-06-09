use futures_util::StreamExt;
use rusty_socks::auth::token::{Claims, TokenManager};
use serde_json::Value;
use tokio_tungstenite::{connect_async, tungstenite::Message};

// Helper to start test server
async fn start_test_server() -> String {
    // Set test configuration
    std::env::set_var("RUSTY_SOCKS_HOST", "127.0.0.1");
    std::env::set_var("RUSTY_SOCKS_PORT", "0"); // Random port
    std::env::set_var("RUSTY_SOCKS_JWT_SECRET", "test-secret-key");

    // TODO: Start server in background and return actual URL
    // For now, this is a placeholder
    "ws://127.0.0.1:3030/ws".to_string()
}

#[tokio::test]
#[ignore = "Requires running server"]
async fn test_anonymous_connection() {
    let url = "ws://127.0.0.1:3030/ws";

    // Connect without token
    let (ws_stream, _) = connect_async(url).await.expect("Failed to connect");
    let (mut _tx, mut rx) = ws_stream.split();

    // Receive welcome message
    if let Some(Ok(Message::Text(msg))) = rx.next().await {
        let data: Value = serde_json::from_str(&msg).expect("Invalid JSON");
        assert_eq!(data["type"], "connected");
        assert_eq!(data["authenticated"], false);
        assert!(data["client_id"].is_string());
    } else {
        panic!("Expected welcome message");
    }
}

#[tokio::test]
#[ignore = "Requires running server"]
async fn test_authenticated_connection() {
    // Create JWT token
    let token_manager = TokenManager::new("test-secret-key");
    let claims = Claims::new(
        "test-user-id".to_string(),
        "testuser".to_string(),
        Some("test@example.com".to_string()),
    ).unwrap();
    let token = token_manager.generate_token(&claims).unwrap();

    // Connect with token in header (secure method)
    let url = "ws://127.0.0.1:3030/ws";
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    
    let mut request = url.into_client_request().expect("Failed to create request");
    request.headers_mut().insert(
        "authorization", 
        HeaderValue::from_str(&format!("Bearer {}", token)).expect("Invalid header value")
    );
    
    let (ws_stream, _) = connect_async(request).await.expect("Failed to connect");
    let (mut _tx, mut rx) = ws_stream.split();

    // Receive welcome message
    if let Some(Ok(Message::Text(msg))) = rx.next().await {
        let data: Value = serde_json::from_str(&msg).expect("Invalid JSON");
        assert_eq!(data["type"], "connected");
        assert_eq!(data["authenticated"], true);
        assert_eq!(data["username"], "testuser");
        assert_eq!(data["client_id"], "test-user-id");
    } else {
        panic!("Expected welcome message");
    }
}

#[tokio::test]
#[ignore = "Requires running server"]
async fn test_invalid_token_rejection() {
    // Connect with invalid token in header (secure method)
    let url = "ws://127.0.0.1:3030/ws";
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    
    let mut request = url.into_client_request().expect("Failed to create request");
    request.headers_mut().insert(
        "authorization", 
        HeaderValue::from_str("Bearer invalid.token.here").expect("Invalid header value")
    );
    
    let (ws_stream, _) = connect_async(request).await.expect("Failed to connect");
    let (mut _tx, mut rx) = ws_stream.split();

    // Should receive error message
    if let Some(Ok(Message::Text(msg))) = rx.next().await {
        let data: Value = serde_json::from_str(&msg).expect("Invalid JSON");
        assert_eq!(data["type"], "error");
        assert_eq!(data["message"], "Authentication failed");
    } else {
        panic!("Expected error message");
    }

    // Connection should close
    assert!(rx.next().await.is_none());
}

#[tokio::test]
#[ignore = "Requires running server"]
async fn test_expired_token_rejection() {
    // Create expired token
    let token_manager = TokenManager::new("test-secret-key");
    let mut claims = Claims::new("test-user-id".to_string(), "testuser".to_string(), None).unwrap();
    claims.exp = claims.iat - 3600; // Expired 1 hour ago

    let token = token_manager.generate_token(&claims).unwrap();

    // Try to connect with expired token in header (secure method)
    let url = "ws://127.0.0.1:3030/ws";
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    
    let mut request = url.into_client_request().expect("Failed to create request");
    request.headers_mut().insert(
        "authorization", 
        HeaderValue::from_str(&format!("Bearer {}", token)).expect("Invalid header value")
    );
    
    let (ws_stream, _) = connect_async(request).await.expect("Failed to connect");
    let (mut _tx, mut rx) = ws_stream.split();

    // Should receive error message
    if let Some(Ok(Message::Text(msg))) = rx.next().await {
        let data: Value = serde_json::from_str(&msg).expect("Invalid JSON");
        assert_eq!(data["type"], "error");
        assert_eq!(data["message"], "Authentication failed");
    } else {
        panic!("Expected error message");
    }
}
