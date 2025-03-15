// tests/websocket_test.rs
//
// Integration test for Rusty Socks WebSocket server
// This test validates the basic connection and message exchange functionality

use std::thread;
use std::time::Duration;
use std::process::{Command, Child};
use tokio::runtime::Runtime;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use serde_json::{json, Value};

// Server process handle for proper cleanup
struct ServerHandle {
    process: Child,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        // Ensure server is terminated when test finishes
        let _ = self.process.kill();
    }
}

// Start the WebSocket server for testing
fn start_server() -> ServerHandle {
    // Build the server if needed (optional)
    let _ = Command::new("cargo")
        .args(["build", "--bin", "rusty_socks"])
        .status()
        .expect("Failed to build the server binary");

    // Start the actual server process
    let process = Command::new("cargo")
        .args(["run", "--bin", "rusty_socks"])
        .spawn()
        .expect("Failed to start Rusty Socks server");

    // Allow time for server initialization
    thread::sleep(Duration::from_secs(2));

    ServerHandle { process }
}

#[test]
fn test_websocket_connection_and_messaging() {
    // Start server in a separate process with automatic cleanup
    let _server = start_server();

    // Create Tokio runtime for async operations
    let rt = Runtime::new().expect("Failed to create Tokio runtime");

    // Run the WebSocket test
    rt.block_on(async {
        // Connection parameters
        let host = "127.0.0.1";
        let port = 3030;
        let url = format!("ws://{}:{}/ws", host, port);

        // Establish WebSocket connection
        let (mut ws_stream, _) = connect_async(url)
            .await
            .expect("Failed to establish WebSocket connection");

        println!("WebSocket connection established");

        // First, we should receive a connection confirmation message
        if let Some(msg) = ws_stream.next().await {
            let msg = msg.expect("Error receiving welcome message");
            assert!(msg.is_text(), "Expected text message for welcome");

            // Parse the welcome message JSON
            let msg_text = msg.into_text().expect("Failed to convert message to text");
            let msg_json: Value = serde_json::from_str(&msg_text)
                .expect("Failed to parse welcome message JSON");

            // Check message structure
            assert!(msg_json.get("type").is_some(), "Missing 'type' field in welcome message");
            assert_eq!(msg_json["type"], "Connect", "Expected Connect message type");
        } else {
            panic!("Did not receive welcome message");
        }

        // Create a test message
        let test_message = json!({
            "sender": "test_client",
            "content": "Hello, Rusty Socks!",
            "timestamp": "2023-07-01T12:00:00Z"
        });

        // Send the test message
        let message_str = test_message.to_string();
        ws_stream.send(Message::Text(message_str))
            .await
            .expect("Failed to send test message");

        println!("Test message sent");

        // Optional: Wait for any response from the server
        if let Some(msg) = ws_stream.next().await {
            let msg = msg.expect("Error receiving response message");
            if msg.is_text() {
                println!("Received response: {}", msg.into_text().unwrap());
            } else {
                println!("Received non-text response");
            }
        }

        // Close the connection gracefully
        ws_stream.close(None).await.expect("Failed to close WebSocket connection");
    });
}

// Test server health endpoint
#[test]
fn test_server_health_endpoint() {
    // Start server with automatic cleanup
    let _server = start_server();

    // Create Tokio runtime
    let rt = Runtime::new().expect("Failed to create Tokio runtime");

    // Test the health endpoint
    rt.block_on(async {
        let client = reqwest::Client::new();
        let response = client.get("http://127.0.0.1:3030/health")
            .send()
            .await
            .expect("Failed to send request to health endpoint");

        assert!(response.status().is_success(), "Health endpoint returned non-success status");

        let body = response.text().await.expect("Failed to read response body");
        assert_eq!(body, "OK", "Health endpoint response should be 'OK'");
    });
}