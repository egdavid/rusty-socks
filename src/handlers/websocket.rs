use tokio::sync::mpsc;
use futures_util::stream::StreamExt;
use futures_util::sink::SinkExt;
use warp::ws::{Message, WebSocket};
use uuid::Uuid;
use log::{info, error, warn, debug};

use crate::core::session::{Sessions, lock_sessions};
use crate::core::message::{SocketMessage, Message as ChatMessage};
use crate::error::RustySocksError;

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
        let mut sessions_guard = match lock_sessions(&sessions) {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to acquire sessions lock for registration: {}", e);
                return;
            }
        };

        if let Err(e) = sessions_guard.register(client_id.clone(), tx.clone()) {
            error!("Failed to register client {}: {}", client_id, e);
            return;
        }

        info!("Client connected: {}", client_id);
        info!("Current connections: {}", sessions_guard.client_count());
    }

    // Send a welcome message to the client
    let connect_msg = SocketMessage::Connect {
        client_id: client_id.clone()
    };

    match serde_json::to_string(&connect_msg) {
        Ok(msg_str) => {
            if let Err(e) = tx.send(Message::text(msg_str)) {
                error!("Failed to send welcome message: {}", e);
            }
        },
        Err(e) => {
            error!("Failed to serialize connect message: {}", e);
        }
    };

    // Retrieve recent messages from the session store
    let recent_messages = match lock_sessions(&sessions) {
        Ok(sessions_guard) => sessions_guard.get_recent_messages(10).unwrap_or_else(|e| {
            error!("Failed to get recent messages: {}", e);
            Vec::new()
        }),
        Err(e) => {
            error!("Failed to acquire sessions lock for recent messages: {}", e);
            Vec::new()
        }
    };

    // Send recent messages to the newly connected client
    for msg in recent_messages {
        let socket_msg = SocketMessage::Chat(msg);
        match serde_json::to_string(&socket_msg) {
            Ok(msg_str) => {
                if let Err(e) = tx.send(Message::text(msg_str)) {
                    error!("Failed to send recent message: {}", e);
                }
            },
            Err(e) => {
                error!("Failed to serialize recent message: {}", e);
            }
        }
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
        match lock_sessions(&sessions) {
            Ok(mut sessions_guard) => {
                if let Err(e) = sessions_guard.unregister(&client_id) {
                    error!("Error unregistering client {}: {}", client_id, e);
                } else {
                    info!("Client disconnected: {}", client_id);
                    info!("Current connections: {}", sessions_guard.client_count());
                }
            },
            Err(e) => {
                error!("Failed to acquire sessions lock for unregistration: {}", e);
            }
        }
    }

    // Broadcast disconnect message
    let disconnect_msg = SocketMessage::Disconnect {
        client_id: client_id.clone()
    };

    match lock_sessions(&sessions) {
        Ok(sessions_guard) => {
            let broadcast_count = sessions_guard.broadcast(&disconnect_msg, &client_id);
            debug!("Broadcast disconnect message to {} clients", broadcast_count);
        },
        Err(e) => {
            error!("Failed to acquire sessions lock for disconnect broadcast: {}", e);
        }
    }
}

// Process an incoming WebSocket message
async fn process_message(msg: Message, client_id: &str, sessions: &Sessions) {
    // Extract the message content
    let msg_str = match msg.to_str() {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to extract text from message: {}", e);
            return;
        }
    };

    // Try to parse as a chat message
    match serde_json::from_str::<ChatMessage>(msg_str) {
        Ok(chat_msg) => {
            // Store the message
            match lock_sessions(sessions) {
                Ok(sessions_guard) => {
                    match sessions_guard.store_message(chat_msg.clone()) {
                        Ok(_) => {
                            // Create a SocketMessage for broadcasting
                            let socket_msg = SocketMessage::Chat(chat_msg);

                            // Broadcast the message
                            let broadcast_count = sessions_guard.broadcast(&socket_msg, client_id);
                            info!("Broadcast message to {} clients from {}", broadcast_count, client_id);
                        },
                        Err(e) => {
                            error!("Failed to store message: {}", e);
                        }
                    }
                },
                Err(e) => {
                    error!("Failed to acquire sessions lock for message processing: {}", e);
                }
            }
        },
        Err(e) => {
            warn!("Failed to parse message: {}", e);
        }
    }
}