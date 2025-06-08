use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use log::{debug, error, info};
use serde_json;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;
use warp::ws::{Message, WebSocket};

use crate::auth::token::TokenManager;
use crate::core::message::SocketMessage;
use crate::core::{MessageHandler, SharedServerManager};
use crate::handlers::auth::authenticate_connection;

// Handle a WebSocket connection
pub async fn handle_ws_client(
    ws: WebSocket,
    server_manager: SharedServerManager,
    token: Option<String>,
    token_manager: Arc<TokenManager>,
) {
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

    // Authenticate the connection
    let user = match authenticate_connection(token, &token_manager).await {
        Ok(user_opt) => {
            if let Some(u) = user_opt {
                info!("Authenticated user: {}", u.username);
                Some(u)
            } else {
                info!("Anonymous connection");
                None
            }
        }
        Err(e) => {
            // Log authentication failure with limited detail for security
            info!("Authentication failed for connection: invalid token");
            debug!("Authentication error details: {}", e);
            
            // Send generic error message to client (no detailed error info)
            let error_msg = serde_json::json!({
                "type": "error",
                "message": "Authentication failed"
            });
            if let Err(send_err) = tx.send(Message::text(error_msg.to_string())) {
                debug!("Failed to send authentication error to client: {}", send_err);
            }
            return;
        }
    };

    // Generate client ID (use user ID if authenticated, otherwise generate new one)
    let client_id = user
        .as_ref()
        .map(|u| u.id.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    // Register the client with integrated server manager
    {
        let result = if let Some(user) = user.clone() {
            server_manager
                .register_authenticated_user(user, tx.clone())
                .await
        } else {
            server_manager
                .register_anonymous_user(client_id.clone(), tx.clone())
                .await
        };

        if let Err(e) = result {
            info!("Failed to register client: connection rejected");
            debug!("Client registration error for {}: {}", client_id, e);
            return;
        }

        info!("Client connected: {}", client_id);
        info!(
            "Current connections: {}",
            server_manager.connection_count().await
        );
    }

    // Send a welcome message to the client
    let welcome_data = if let Some(user) = &user {
        serde_json::json!({
            "type": "connected",
            "client_id": client_id.clone(),
            "authenticated": true,
            "username": user.username,
            "global_role": user.global_role
        })
    } else {
        serde_json::json!({
            "type": "connected",
            "client_id": client_id.clone(),
            "authenticated": false
        })
    };

    match serde_json::to_string(&welcome_data) {
        Ok(msg_str) => {
            if let Err(e) = tx.send(Message::text(msg_str)) {
                debug!("Failed to send welcome message: {}", e);
            }
        }
        Err(e) => {
            debug!("Failed to serialize connect message: {}", e);
        }
    };

    // Send recent messages to the newly connected client
    match server_manager.get_recent_messages(10).await {
        Ok(recent_messages) => {
            for msg in recent_messages {
                let socket_msg = SocketMessage::Chat(msg);
                match serde_json::to_string(&socket_msg) {
                    Ok(msg_str) => {
                        if let Err(e) = tx.send(Message::text(msg_str)) {
                            debug!("Failed to send recent message: {}", e);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to serialize recent message: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            debug!("Failed to get recent messages: {}", e);
        }
    }

    // Create message handler for this connection
    let message_handler = MessageHandler::new(server_manager.clone());

    // Handle incoming messages
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(msg) => {
                // Only process text messages
                if msg.is_text() {
                    if let Ok(text) = msg.to_str() {
                        if let Err(e) = message_handler
                            .handle_client_message(&client_id, text)
                            .await
                        {
                            debug!("Message handling error from {}: {}", client_id, e);
                        }
                    }
                }
            }
            Err(e) => {
                debug!("WebSocket connection error: {}", e);
                break;
            }
        }
    }

    // Cleanup on disconnect
    if let Err(e) = server_manager.unregister_user(&client_id).await {
        info!("Failed to cleanup client: connection cleanup error");
        debug!("Cleanup error for client {}: {}", client_id, e);
    } else {
        info!("Client disconnected successfully");
        debug!("Client {} disconnected", client_id);
        info!(
            "Current connections: {}",
            server_manager.connection_count().await
        );
    }
}
