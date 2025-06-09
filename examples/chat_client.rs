//! Simple chat client example
//! 
//! This example demonstrates how to build a basic chat application
//! using rusty-socks WebSocket server.

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::io::{self, Write};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_tungstenite::{connect_async, tungstenite::Message};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    println!("🧦 Rusty Socks Chat Client");
    println!("Connecting to ws://127.0.0.1:8080/ws");
    
    // Connect to the WebSocket server
    let (ws_stream, _) = connect_async("ws://127.0.0.1:8080/ws")
        .await
        .expect("Failed to connect to WebSocket server");
    
    println!("✅ Connected to server!");
    
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    
    // Get username from user
    print!("Enter your username: ");
    io::stdout().flush().unwrap();
    let mut username = String::new();
    io::stdin().read_line(&mut username).unwrap();
    let username = username.trim().to_string();
    
    // Join the general room
    let join_message = json!({
        "type": "join_room",
        "room_id": "general"
    });
    
    ws_sender
        .send(Message::Text(join_message.to_string()))
        .await?;
    
    println!("📝 Type messages to send them to the 'general' room");
    println!("📝 Use /join <room> to join a different room");
    println!("📝 Use /create <room_name> to create a new room");
    println!("📝 Use /quit to exit");
    println!();
    
    // Handle user input
    let stdin = tokio::io::stdin();
    let mut stdin_reader = BufReader::new(stdin).lines();
    
    let mut current_room = "general".to_string();
    
    loop {
        tokio::select! {
            // Handle incoming WebSocket messages
            ws_message = ws_receiver.next() => {
                match ws_message {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(msg) = serde_json::from_str::<Value>(&text) {
                            handle_server_message(&msg);
                        } else {
                            println!("📨 Raw message: {}", text);
                        }
                    }
                    Some(Ok(Message::Close(_))) => {
                        println!("🔌 Connection closed by server");
                        break;
                    }
                    Some(Err(e)) => {
                        println!("❌ WebSocket error: {}", e);
                        break;
                    }
                    None => {
                        println!("🔌 Connection terminated");
                        break;
                    }
                    _ => {}
                }
            }
            
            // Handle user input
            line = stdin_reader.next_line() => {
                match line {
                    Ok(Some(input)) => {
                        let input = input.trim();
                        
                        if input == "/quit" {
                            break;
                        } else if input.starts_with("/join ") {
                            let room_name = input.strip_prefix("/join ").unwrap_or("general");
                            current_room = room_name.to_string();
                            
                            let join_msg = json!({
                                "type": "join_room",
                                "room_id": room_name
                            });
                            
                            if let Err(e) = ws_sender.send(Message::Text(join_msg.to_string())).await {
                                println!("❌ Failed to send join message: {}", e);
                            }
                        } else if input.starts_with("/create ") {
                            let room_name = input.strip_prefix("/create ").unwrap_or("new_room");
                            
                            let create_msg = json!({
                                "type": "create_room",
                                "name": room_name,
                                "max_members": 50
                            });
                            
                            if let Err(e) = ws_sender.send(Message::Text(create_msg.to_string())).await {
                                println!("❌ Failed to send create message: {}", e);
                            }
                        } else if input.starts_with("/list") {
                            let list_msg = json!({
                                "type": "list_rooms"
                            });
                            
                            if let Err(e) = ws_sender.send(Message::Text(list_msg.to_string())).await {
                                println!("❌ Failed to send list message: {}", e);
                            }
                        } else if !input.is_empty() {
                            // Send regular message
                            let message = json!({
                                "type": "room_message",
                                "room_id": current_room,
                                "content": format!("[{}]: {}", username, input)
                            });
                            
                            if let Err(e) = ws_sender.send(Message::Text(message.to_string())).await {
                                println!("❌ Failed to send message: {}", e);
                            }
                        }
                    }
                    Ok(None) => {
                        println!("📝 Input stream ended");
                        break;
                    }
                    Err(e) => {
                        println!("❌ Input error: {}", e);
                        break;
                    }
                }
            }
        }
    }
    
    println!("👋 Goodbye!");
    Ok(())
}

fn handle_server_message(msg: &Value) {
    match msg.get("type").and_then(|t| t.as_str()) {
        Some("room_message") => {
            let room = msg.get("room_id").and_then(|r| r.as_str()).unwrap_or("unknown");
            let sender = msg.get("sender_username").and_then(|s| s.as_str()).unwrap_or("unknown");
            let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
            let timestamp = msg.get("timestamp").and_then(|t| t.as_str()).unwrap_or("");
            
            println!("💬 [{}] {}: {}", room, sender, content);
            if !timestamp.is_empty() {
                println!("   📅 {}", timestamp);
            }
        }
        
        Some("user_joined") => {
            let room = msg.get("room_id").and_then(|r| r.as_str()).unwrap_or("unknown");
            let username = msg.get("username").and_then(|u| u.as_str()).unwrap_or("unknown");
            println!("👋 {} joined {}", username, room);
        }
        
        Some("user_left") => {
            let room = msg.get("room_id").and_then(|r| r.as_str()).unwrap_or("unknown");
            let username = msg.get("username").and_then(|u| u.as_str()).unwrap_or("unknown");
            println!("👋 {} left {}", username, room);
        }
        
        Some("success") => {
            let message = msg.get("message").and_then(|m| m.as_str()).unwrap_or("");
            println!("✅ {}", message);
        }
        
        Some("error") => {
            let code = msg.get("code").and_then(|c| c.as_str()).unwrap_or("UNKNOWN");
            let message = msg.get("message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
            println!("❌ {}: {}", code, message);
        }
        
        Some("room_list") => {
            if let Some(rooms) = msg.get("rooms").and_then(|r| r.as_array()) {
                println!("📋 Available rooms:");
                for room in rooms {
                    let name = room.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                    let id = room.get("id").and_then(|i| i.as_str()).unwrap_or("unknown");
                    let member_count = room.get("member_count").and_then(|c| c.as_u64()).unwrap_or(0);
                    println!("   🏠 {} ({}) - {} members", name, id, member_count);
                }
            }
        }
        
        Some("private_message") => {
            let sender = msg.get("sender_username").and_then(|s| s.as_str()).unwrap_or("unknown");
            let content = msg.get("content").and_then(|c| c.as_str()).unwrap_or("");
            println!("💌 Private from {}: {}", sender, content);
        }
        
        _ => {
            println!("📨 Server: {}", msg);
        }
    }
}