use tokio::sync::mpsc;
use futures_util::stream::StreamExt;
use futures_util::sink::SinkExt;
use warp::ws::{Message, WebSocket};
use uuid::Uuid;
use log::{info, error, warn};

use crate::core::session::{Sessions};
use crate::core::message::{SocketMessage, Message as ChatMessage};
use crate::core::connection::Connection;

// Handle a WebSocket connection
pub async fn handle_ws_client(ws: WebSocket, sessions: Sessions) {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (tx, rx) = mpsc::unbounded_channel();

    // Spawn a task to forward messages from our channel to the WebSocket
    tokio::task::spawn(async move {
        let mut rx = rx;
        while let Some(message) = rx.recv().await {
            if let Err(e) = ws_tx.send(message).await {
                error!("Failed to send WebSocket message: {}", e);
                break;
            }
        }
    });

    // Generate a unique client ID
    let client_id = Uuid::new_v4().to_string();

    // Register the client
    {
        let mut sessions = sessions.lock().unwrap();
        sessions.register(client_id.clone(), tx.clone());
        info!("Client connected: {}", client_id);
        info!("Current connections: {}", sessions.client_count());
    }

    // Send a welcome message to the client
    let connect_msg = SocketMessage::Connect {
        client_id: client_id.clone()
    };

    if let Ok(msg_str) = serde_json::to_string(&connect_msg) {
        let _ = tx.send(Message::text(msg_str));
    }

    // Handle incoming messages
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                // Only process text messages
                if msg.is_text() {
                    process_message(msg, &client_id, &sessions).await;
                }
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
        }
    }

    // Client disconnected
    {
        let mut sessions = sessions.lock().unwrap();
        sessions.unregister(&client_id);
        info!("Client disconnected: {}", client_id);
        info!("Current connections: {}", sessions.client_count());
    }

    // Broadcast disconnect message
    let disconnect_msg = SocketMessage::Disconnect {
        client_id: client_id.clone()
    };

    if let Ok(sessions) = sessions.lock() {
        sessions.broadcast(&disconnect_msg, &client_id);
    }
}

async fn process_message(msg: Message, client_id: &str, sessions: &Sessions) {
    // Extract the message content
    let msg_str = match msg.to_str() {
        Ok(s) => s,
        Err(_) => return,
    };

    // Try to parse as a chat message
    match serde_json::from_str::<ChatMessage>(msg_str) {
        Ok(chat_msg) => {
            // Create a SocketMessage to broadcast
            let socket_msg = SocketMessage::Chat(chat_msg);

            // Broadcast to all clients
            if let Ok(sessions) = sessions.lock() {
                let broadcast_count = sessions.broadcast(&socket_msg, client_id);
                info!("Message from client {} broadcasted to {} clients", client_id, broadcast_count);
            } else {
                error!("Failed to acquire lock on sessions");
            }
        },
        Err(e) => {
            warn!("Failed to parse message: {}", e);
        }
    }
}