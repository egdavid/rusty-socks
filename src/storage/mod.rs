//! Storage mechanisms for persisting and retrieving messages

pub mod message_store;

// Re-export the message store
pub use message_store::MessageStore;