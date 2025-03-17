use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use warp::ws::Message as WsMessage;

use crate::core::connection::Connection;
use crate::core::message::SocketMessage;

// Represents a client connection with its associated sender channel
pub struct Client {
    pub id: String,
    pub sender: mpsc::UnboundedSender<WsMessage>,
}

// Manages multiple client connections and their state
pub struct SessionManager {
    connections: HashMap<String, Connection>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    // Register a new client connection
    pub fn register(&mut self, id: String, sender: mpsc::UnboundedSender<WsMessage>) {
        let connection = Connection::with_id(id.clone(), sender);
        self.connections.insert(id, connection);
    }

    // Remove a client connection
    pub fn unregister(&mut self, id: &str) { self.connections.remove(id); }

    // Broadcast a message to all connected clients
    pub fn broadcast(&self, message: &SocketMessage, sender_id: &str) -> usize {
        let message_str = serde_json::to_string(message).unwrap_or_default();
        let ws_message = WsMessage::text(message_str);

        let mut success_count = 0;

        for (id, connection) in &self.connections {
            // Don't send the message back to its sender
            if id != sender_id {
                if connection.sender.send(ws_message.clone()).is_ok() {
                    success_count += 1;
                }
            }
        }

        success_count
    }

    // Get current clients count
    pub fn client_count(&self) -> usize {
        self.connections.len()
    }

    /// Check for stale connections and return their IDs
    pub fn check_stale_connections(&self, timeout: std::time::Duration) -> Vec<String> {
        self.connections
            .iter()
            .filter(|(_, conn)| conn.is_stale(timeout))
            .map(|(id, _)| id.clone())
            .collect()
    }
}

// Thread-safe session manager wrapper
pub type Sessions = Arc<Mutex<SessionManager>>;

// Create a new thread-safe session manager
pub fn create_session_manager() -> Sessions {
    Arc::new(Mutex::new(SessionManager::new()))
}