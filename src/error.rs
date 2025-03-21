use std::fmt;
use std::error::Error;
use std::sync::PoisonError;

#[derive(Debug)]
pub enum RustySocksError {
    // Session errors
    SessionLock(String),
    SessionNotFound(String),

    // Connections errors
    ConnectionError(String),
    ConnectionClosed,

    // Storage errors
    StorageError(String),

    // Messages errors
    MessageParseError(String),
    MessageTooLarge(usize),

    // System errors
    SystemError(String),
}

impl fmt::Display for RustySocksError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionLock(msg) => write!(f, "Session lock error: {}", msg),
            Self::SessionNotFound(id) => write!(f, "Session not found: {}", id),
            Self::ConnectionError(msg) => write!(f, "Connection error: {}", msg),
            Self::ConnectionClosed => write!(f, "Connection closed unexpectedly"),
            Self::StorageError(msg) => write!(f, "Storage error: {}", msg),
            Self::MessageParseError(msg) => write!(f, "Message parse error: {}", msg),
            Self::MessageTooLarge(size) => write!(f, "Message too large: {} bytes", size),
            Self::SystemError(msg) => write!(f, "System error: {}", msg),
        }
    }
}

impl Error for RustySocksError {}

// Converting from PoisonError to facilitate poisoned mutex handling
impl<T> From<PoisonError<T>> for RustySocksError {
    fn from(err: PoisonError<T>) -> Self {
        RustySocksError::SessionLock(format!("Mutex poisoned: {}", err))
    }
}

// Generic result type for RustySocks
pub type Result<T> = std::result::Result<T, RustySocksError>;