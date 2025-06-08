// Integration test for Rusty Socks WebSocket server
// This test validates the basic connection and message exchange functionality

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

// Server process handle for proper cleanup
struct ServerHandle {
    process: Child,
    port: u16,
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
fn start_server(port: u16) -> Result<ServerHandle, String> {
    // Build the server if needed
    let build_status = Command::new("cargo")
        .args(["build", "--bin", "rusty_socks"])
        .status()
        .map_err(|e| format!("Failed to execute build command: {}", e))?;

    if !build_status.success() {
        return Err(format!(
            "Build process failed with exit code: {:?}",
            build_status.code()
        ));
    }

    println!("Starting server on port {}", port);

    // Start the actual server process with specified port
    let process = Command::new("cargo")
        .args(["run", "--bin", "rusty_socks"])
        .env("RUSTY_SOCKS_HOST", "127.0.0.1")
        .env("RUSTY_SOCKS_PORT", port.to_string())
        .env("RUSTY_SOCKS_JWT_SECRET", "test-secret-key")
        .env("RUST_LOG", "debug")
        .spawn()
        .map_err(|e| format!("Failed to start Rusty Socks server: {}", e))?;

    // Allow time for server initialization
    thread::sleep(Duration::from_secs(5));

    // Verify server availability
    match reqwest::blocking::Client::new()
        .get(format!("http://127.0.0.1:{}/health", port))
        .timeout(Duration::from_secs(1))
        .send()
    {
        Ok(_) => println!("Server successfully booted on port {}", port),
        Err(e) => println!("Warning: Unable to verify server status: {}", e),
    }

    Ok(ServerHandle { process, port })
}

// Test WebSocket connection establishment and basic message exchange
#[test]
fn test_websocket_connection_and_messaging() {
    // Start server on a specific port
    let port = 3031;
    let _server = match start_server(port) {
        Ok(server) => server,
        Err(e) => {
            panic!("Failed to start test server: {}", e);
        }
    };

    // First check server health outside async context
    // This avoids runtime conflicts with blocking calls
    let health_check = reqwest::blocking::Client::new()
        .get(format!("http://127.0.0.1:{}/health", port))
        .timeout(Duration::from_secs(2))
        .send();

    match health_check {
        Ok(response) => println!("Server status: {}", response.status()),
        Err(e) => println!("Health check failed: {}", e),
    }

    // Create Tokio runtime for async operations
    let rt = match Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            panic!("Failed to create Tokio runtime: {}", e);
        }
    };

    // Run the WebSocket test
    rt.block_on(async {
        // Connection parameters
        let host = "127.0.0.1";
        let url = format!("ws://{}:{}/ws", host, port);

        println!("Connecting to URL: {}", url);

        // Establish WebSocket connection with explicit timeout
        // This prevents indefinite blocking if server doesn't respond
        let (mut ws_stream, _) =
            match tokio::time::timeout(Duration::from_secs(5), connect_async(url)).await {
                Ok(conn_result) => match conn_result {
                    Ok(ws) => ws,
                    Err(e) => {
                        panic!("Failed to establish WebSocket connection: {}", e);
                    }
                },
                Err(_) => {
                    panic!("WebSocket connection timeout after 5 seconds");
                }
            };

        println!("WebSocket connection established");

        // First, we should receive a connection confirmation message
        let welcome_message = match ws_stream.next().await {
            Some(result) => match result {
                Ok(msg) => msg,
                Err(e) => panic!("Error receiving welcome message: {}", e),
            },
            None => panic!("Did not receive welcome message, connection closed unexpectedly"),
        };

        assert!(
            welcome_message.is_text(),
            "Expected text message for welcome"
        );

        // Parse the welcome message JSON
        let msg_text = match welcome_message.into_text() {
            Ok(text) => text,
            Err(e) => panic!("Failed to convert message to text: {}", e),
        };

        let msg_json: Value = match serde_json::from_str(&msg_text) {
            Ok(json) => json,
            Err(e) => panic!("Failed to parse welcome message JSON: {}", e),
        };

        // Check message structure
        assert!(
            msg_json.get("type").is_some(),
            "Missing 'type' field in welcome message"
        );
        assert_eq!(msg_json["type"], "connected", "Expected connected message type");

        // Create a test message that matches expected server structure
        // Let's request the list of rooms as a simple test
        let test_message = json!({
            "type": "list_rooms"
        });

        // Send the test message
        let message_str = test_message.to_string();
        if let Err(e) = ws_stream.send(Message::Text(message_str)).await {
            panic!("Failed to send test message: {}", e);
        }

        println!("Test message sent");

        // Wait for any response with robust timeout handling
        match tokio::time::timeout(Duration::from_secs(3), ws_stream.next()).await {
            Ok(Some(Ok(msg))) => {
                if msg.is_text() {
                    match msg.into_text() {
                        Ok(text) => println!("Received response: {}", text),
                        Err(e) => println!("Failed to convert response to text: {}", e),
                    }
                } else {
                    println!("Received non-text response");
                }
            }
            Ok(Some(Err(e))) => println!("Error receiving response: {}", e),
            Ok(None) => println!("Connection closed without response"),
            Err(_) => println!("Timeout waiting for server response"),
        }

        // Close the connection gracefully
        if let Err(e) = ws_stream.close(None).await {
            println!(
                "Warning: Failed to close WebSocket connection gracefully: {}",
                e
            );
        }
    });
}

// Test the server health endpoint to ensure basic HTTP functionality
#[test]
fn test_server_health_endpoint() {
    // Start server on a different port
    let port = 3032;
    let _server = match start_server(port) {
        Ok(server) => server,
        Err(e) => {
            panic!("Failed to start test server: {}", e);
        }
    };

    // Create Tokio runtime
    let rt = match Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            panic!("Failed to create Tokio runtime: {}", e);
        }
    };

    // Test the health endpoint
    rt.block_on(async {
        let client = reqwest::Client::new();
        let response = match client
            .get(format!("http://127.0.0.1:{}/health", port))
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => panic!("Failed to send request to health endpoint: {}", e),
        };

        assert!(
            response.status().is_success(),
            "Health endpoint returned non-success status"
        );

        let body = match response.text().await {
            Ok(text) => text,
            Err(e) => panic!("Failed to read response body: {}", e),
        };

        assert_eq!(body, "OK", "Health endpoint response should be 'OK'");
    });
}
