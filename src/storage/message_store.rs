//! Simple in-memory storage for recent messages
//!
//! This implementation provides a basic circular buffer for storing
//! recent messages without persisting to disk.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use crate::core::message::Message;

/// Maximum number of messages to store in memory
const DEFAULT_MAX_MESSAGES: usize = 100;

/// Simple in-memory message store with a maximum capacity
pub struct MessageStore {
    messages: VecDeque<Message>,
    max_size: usize,
}

impl MessageStore {
    /// Create a new message store with default capacity
    pub fn new() -> Self {
        Self {
            messages: VecDeque::with_capacity(DEFAULT_MAX_MESSAGES),
            max_size: DEFAULT_MAX_MESSAGES,
        }
    }

    /// Create a message store with custom capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            messages: VecDeque::with_capacity(capacity),
            max_size: capacity,
        }
    }

    /// Add a message to the store, removing oldest if at capacity
    pub fn add_message(&mut self, message: Message) {
        // If at capacity, remove the oldest message
        if self.messages.len() >= self.max_size {
            self.messages.pop_front();
        }

        // Add the new message
        self.messages.push_back(message);
    }

    /// Get recent messages up to a specified limit
    pub fn recent_messages(&self, limit: usize) -> Vec<Message> {
        let actual_limit = limit.min(self.messages.len());

        // Get the most recent messages
        self.messages
            .iter()
            .rev()
            .take(actual_limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    /// Get all messages
    pub fn all_messages(&self) -> Vec<Message> {
        self.messages.iter().cloned().collect()
    }

    /// Clear all messages
    pub fn clear(&mut self) {
        self.messages.clear();
    }

    /// Get the number of stored messages
    pub fn count(&self) -> usize {
        self.messages.len()
    }
}

/// Thread-safe wrapper for MessageStore
pub type SharedMessageStore = Arc<Mutex<MessageStore>>;

/// Create a new thread-safe message store
pub fn create_message_store() -> SharedMessageStore {
    Arc::new(Mutex::new(MessageStore::new()))
}

/// Create a new thread-safe message store with custom capacity
pub fn create_message_store_with_capacity(capacity: usize) -> SharedMessageStore {
    Arc::new(Mutex::new(MessageStore::with_capacity(capacity)))
}