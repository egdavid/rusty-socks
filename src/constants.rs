// Fundamental configuration constants
// SECURITY: Default to localhost for security - external access requires explicit configuration
pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 3030;
pub const WS_PATH: &str = "ws";

// Thread pool configuration constants
pub const DEFAULT_THREAD_POOL_SIZE: usize = 4;
pub const DEFAULT_MAX_QUEUED_TASKS: usize = 1000;
