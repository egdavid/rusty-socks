use log::{debug, error};
use std::collections::HashMap;
use tokio::sync::mpsc;
use warp::ws::Message as WsMessage;

use crate::core::connection::Connection;
use crate::core::message::SocketMessage;
use crate::error::{Result, RustySocksError};
use crate::storage;

// Manages multiple client connections and their state
pub struct SessionManager {
    connections: HashMap<String, Connection>,
    message_store: Option<storage::message_store::SharedMessageStore>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
            message_store: None,
        }
    }

    // Set the message store
    pub fn set_message_store(&mut self, message_store: storage::message_store::SharedMessageStore) {
        self.message_store = Some(message_store);
    }

    // Get the message store
    pub fn get_message_store(&self) -> Option<&storage::message_store::SharedMessageStore> {
        self.message_store.as_ref()
    }

    pub fn store_message(&self, message: crate::core::message::Message) -> Result<bool> {
        if let Some(store) = &self.message_store {
            let mut store_guard = store.lock().map_err(|e| {
                RustySocksError::StorageError(format!("Failed to lock message store: {}", e))
            })?;
            store_guard.add_message(message);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // Parameterized constructor (controls the way store is injected)
    pub fn with_message_store(message_store: storage::message_store::SharedMessageStore) -> Self {
        Self {
            connections: HashMap::new(),
            message_store: Some(message_store),
        }
    }

    pub fn get_recent_messages(&self, limit: usize) -> Result<Vec<crate::core::message::Message>> {
        if let Some(store) = &self.message_store {
            let store_guard = store.lock().map_err(|e| {
                RustySocksError::StorageError(format!("Failed to lock message store: {}", e))
            })?;
            Ok(store_guard.recent_messages(limit))
        } else {
            Ok(Vec::new())
        }
    }

    // Register a new client connection
    pub fn register(&mut self, id: String, sender: mpsc::UnboundedSender<WsMessage>) -> Result<()> {
        let connection = Connection::with_id(id.clone(), sender);
        self.connections.insert(id.clone(), connection);
        debug!("Client registered: {}", id);
        Ok(())
    }

    // Register an authenticated client connection
    pub fn register_authenticated(
        &mut self,
        user: crate::auth::user::User,
        sender: mpsc::UnboundedSender<WsMessage>,
    ) -> Result<()> {
        let connection = Connection::authenticated(user.clone(), sender);
        self.connections.insert(user.id.clone(), connection);
        debug!(
            "Authenticated client registered: {} ({})",
            user.id, user.username
        );
        Ok(())
    }

    // Get connection by ID
    pub fn get_connection(&self, id: &str) -> Option<&Connection> {
        self.connections.get(id)
    }

    // Get mutable connection by ID
    pub fn get_connection_mut(&mut self, id: &str) -> Option<&mut Connection> {
        self.connections.get_mut(id)
    }

    // Remove a client connection
    pub fn unregister(&mut self, id: &str) -> Result<bool> {
        let was_present = self.connections.remove(id).is_some();
        if was_present {
            debug!("Client unregistered: {}", id);
        }
        Ok(was_present)
    }
    
    // Get user information (username) for display purposes
    pub fn get_user_info(&self, user_id: &str) -> Option<String> {
        // Return a placeholder since we don't store user data in sessions
        // TODO: Integrate with proper user storage/authentication system
        if self.connections.contains_key(user_id) {
            Some(format!("User_{}", &user_id[..8])) // Show first 8 chars of ID
        } else {
            None
        }
    }

    // Broadcast a message to all connected clients
    pub fn broadcast(&self, message: &SocketMessage, sender_id: &str) -> usize {
        let message_str = match serde_json::to_string(message) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to serialize message: {}", e);
                return 0;
            }
        };
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

// NOTE: SessionManager is now integrated into ServerManager with async RwLock
// The standalone Sessions type is deprecated in favor of unified architecture
