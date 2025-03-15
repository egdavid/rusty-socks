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
use uuid::Uuid;
use chrono::Utc;

// Server process handle for proper cleanup
struct ServerHandle {
    process: Child,
    port: u16
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        // Terminate the process forcefully
        if let Err(e) = self.process.kill() {
            println!("Error during process termination: {}", e);
        }

        // Wait for the process to completely terminate
        if let Err(e) = self.process.wait() {
            println!("Error waiting for process to finish: {}", e);
        }

        // Wait for the port to be freed
        thread::sleep(Duration::from_secs(1));

        println!("Server on port {} has been properly stopped", self.port);
    }
}

// Start the WebSocket server for testing
fn start_server(port: u16) -> ServerHandle {
    // Build the server if needed
    let _ = Command::new("cargo")
        .args(["build", "--bin", "rusty_socks"])
        .status()
        .expect("Failed to build the server binary");

    println!("Starting server on port {}", port);

    // Start the actual server process with specified port
    let process = Command::new("cargo")
        .args(["run", "--bin", "rusty_socks"])
        .env("RUSTY_SOCKS_HOST", "127.0.0.1")
        .env("RUSTY_SOCKS_PORT", port.to_string())
        .env("RUST_LOG", "debug")
        .spawn()
        .expect("Failed to start Rusty Socks server");

    // Allow time for server initialization
    thread::sleep(Duration::from_secs(5));

    // Verify server availability
    match reqwest::blocking::Client::new()
        .get(format!("http://127.0.0.1:{}/health", port))
        .timeout(Duration::from_secs(1))
        .send() {
        Ok(_) => println!("Server successfully booted on port {}", port),
        Err(e) => println!("Warning: Unable to verify server status: {}", e)
    }

    ServerHandle { process, port }
}

#[test]
fn test_websocket_connection_and_messaging() {
    // Start server on a specific port
    let port = 3031;
    let _server = start_server(port);

    // First check server health outside of async context
    // This avoids runtime conflicts with blocking calls
    let health_check = reqwest::blocking::Client::new()
        .get(format!("http://127.0.0.1:{}/health", port))
        .timeout(Duration::from_secs(2))
        .send();

    match health_check {
        Ok(response) => println!("Server status: {}", response.status()),
        Err(e) => println!("Health check failed: {}", e)
    }

    // Create Tokio runtime for async operations
    let rt = Runtime::new().expect("Failed to create Tokio runtime");

    // Run the WebSocket test
    rt.block_on(async {
        // Connection parameters
        let host = "127.0.0.1";
        let url = format!("ws://{}:{}/ws", host, port);

        println!("Connecting to URL: {}", url);

        // Establish WebSocket connection with explicit timeout
        // This prevents indefinite blocking if server doesn't respond
        let (mut ws_stream, _) = tokio::time::timeout(
            Duration::from_secs(5),
            connect_async(url)
        ).await
            .expect("WebSocket connection timeout")
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

        // Create a test message that matches expected server structure
        let test_message = json!({
            "id": Uuid::new_v4(),
            "sender": "test_client",
            "content": "Hello, Rusty Socks!",
            "timestamp": Utc::now()
        });

        // Send the test message
        let message_str = test_message.to_string();
        ws_stream.send(Message::Text(message_str))
            .await
            .expect("Failed to send test message");

        println!("Test message sent");

        // Wait for any response with robust timeout handling
        match tokio::time::timeout(Duration::from_secs(3), ws_stream.next()).await {
            Ok(Some(Ok(msg))) => {
                if msg.is_text() {
                    println!("Received response: {}", msg.into_text().unwrap());
                } else {
                    println!("Received non-text response");
                }
            },
            Ok(Some(Err(e))) => println!("Error receiving response: {}", e),
            Ok(None) => println!("Connection closed without response"),
            Err(_) => println!("Timeout waiting for server response")
        }

        // Close the connection gracefully
        ws_stream.close(None).await.expect("Failed to close WebSocket connection");
    });
}

#[test]
fn test_server_health_endpoint() {
    // Start server on a different port
    let port = 3032;
    let _server = start_server(port);

    // Create Tokio runtime
    let rt = Runtime::new().expect("Failed to create Tokio runtime");

    // Test the health endpoint
    rt.block_on(async {
        let client = reqwest::Client::new();
        let response = client.get(format!("http://127.0.0.1:{}/health", port))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .expect("Failed to send request to health endpoint");

        assert!(response.status().is_success(), "Health endpoint returned non-success status");

        let body = response.text().await.expect("Failed to read response body");
        assert_eq!(body, "OK", "Health endpoint response should be 'OK'");
    });
}