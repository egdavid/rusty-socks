//! Storage mechanisms for persisting and retrieving messages

pub mod memory;
pub mod message_store;
pub mod token_revocation;
pub mod traits;

// Re-export main components
pub use memory::MemoryStorageProvider;
pub use message_store::{
    MessageStore, MessageStoreConfig, MessageStoreStats, SharedMessageStore,
    create_message_store, create_message_store_with_config, create_message_store_with_capacity,
    add_message_async, recent_messages_async, all_messages_async, clear_async, count_async,
    cleanup_async, cleanup_by_memory_pressure_async, get_stats_async, needs_cleanup_async,
    update_config_async, trigger_background_cleanup
};
pub use traits::{StorageProvider, StorageConfig, MessageStorage, RoomStorage, UserStorage};
