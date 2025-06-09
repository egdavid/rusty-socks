//! WebSocket connection management
//! Handles the lifecycle of client connections

use log::warn;
use std::net::IpAddr;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use uuid::Uuid;
use warp::ws::Message;

use crate::auth::user::User;

/// Represents the state of a single WebSocket connection
pub struct Connection {
    pub id: String,
    pub sender: mpsc::UnboundedSender<Message>,
    pub connected_at: Instant,
    pub last_ping: Instant,
    pub user: Option<User>,
    pub client_ip: IpAddr,
}

impl Connection {
    /// Create a new connection with a unique ID
    pub fn new(sender: mpsc::UnboundedSender<Message>, client_ip: IpAddr) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            sender,
            connected_at: Instant::now(),
            last_ping: Instant::now(),
            user: None,
            client_ip,
        }
    }

    /// Create a new connection with a specific ID
    pub fn with_id(id: String, sender: mpsc::UnboundedSender<Message>, client_ip: IpAddr) -> Self {
        Self {
            id,
            sender,
            connected_at: Instant::now(),
            last_ping: Instant::now(),
            user: None,
            client_ip,
        }
    }

    /// Create a new authenticated connection
    pub fn authenticated(user: User, sender: mpsc::UnboundedSender<Message>, client_ip: IpAddr) -> Self {
        Self {
            id: user.id.clone(),
            sender,
            connected_at: Instant::now(),
            last_ping: Instant::now(),
            user: Some(user),
            client_ip,
        }
    }

    /// Set the user for this connection
    pub fn set_user(&mut self, user: User) {
        self.user = Some(user);
    }

    /// Check if connection is authenticated
    pub fn is_authenticated(&self) -> bool {
        self.user.is_some()
    }

    /// Send a text message through this connection
    pub fn send_text(&self, text: &str) -> bool {
        match self.sender.send(Message::text(text)) {
            Ok(_) => true,
            Err(_) => {
                warn!("Failed to send message to client {}", self.id);
                false
            }
        }
    }

    /// Send a binary message through this connection
    pub fn send_binary(&self, data: Vec<u8>) -> bool {
        match self.sender.send(Message::binary(data)) {
            Ok(_) => true,
            Err(_) => {
                warn!("Failed to send binary data to client {}", self.id);
                false
            }
        }
    }

    /// Update the last ping time
    pub fn update_ping(&mut self) {
        self.last_ping = Instant::now();
    }

    /// Check if the connection is stale (no ping for a while)
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_ping.elapsed() > timeout
    }

    /// Calculate the connection duration
    pub fn connection_duration(&self) -> Duration {
        self.connected_at.elapsed()
    }
}
