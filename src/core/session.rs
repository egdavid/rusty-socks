use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use warp::ws::Message as WsMessage;

use crate::core::message::SocketMessage;

// Represents a client connection with its associated sender channel
pub struct Client {
    pub id: String,
    pub sender: mpsc::UnboundedSender<WsMessage>,
}

// Manages multiple client connections and their state
pub struct SessionManager {
    clients: HashMap<String, mpsc::UnboundedSender<WsMessage>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            clients: HashMap::new(),
        }
    }

    // Register a new client connection
    pub fn register(&mut self, id: String, sender: mpsc::UnboundedSender<WsMessage>) {
        self.clients.insert(id, sender);
    }

    // Remove a client connection
    pub fn unregister(&mut self, id: &str) {
        self.clients.remove(id);
    }

    // Broadcast a message to all connected clients
    pub fn broadcast(&self, message: &SocketMessage, sender_id: &str) -> usize {
        let message_str = serde_json::to_string(message).unwrap_or_default();
        let ws_message = WsMessage::text(message_str);

        let mut success_count = 0;

        for (id, tx) in &self.clients {
            // Don't send the message back to its sender
            if id != sender_id {
                if tx.send(ws_message.clone()).is_ok() {
                    success_count += 1;
                }
            }
        }

        success_count
    }

    // Get current clients count
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }
}

// Thread-safe session manager wrapper
pub type Sessions = Arc<Mutex<SessionManager>>;

// Create a new thread-safe session manager
pub fn create_session_manager() -> Sessions {
    Arc::new(Mutex::new(SessionManager::new()))
}