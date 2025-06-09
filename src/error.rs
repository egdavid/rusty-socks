use std::error::Error;
use std::fmt;
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

    // Room errors
    RoomNotFound,
    RoomFull,
    CannotDeleteDefaultRoom,

    // Auth errors
    AuthError(String),
    AuthenticationError(String),
    Unauthorized,
    Forbidden,
    PermissionDenied(String),

    // Validation errors
    ValidationError(String),

    // System errors
    SystemError(String),
    
    // Configuration errors
    ConfigError(String),
    
    // Additional errors
    NotImplemented(String),
    RegistrationError(String),
    NotFound(String),
    ConflictError(String),
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
            Self::RoomNotFound => write!(f, "Room not found"),
            Self::RoomFull => write!(f, "Room is full"),
            Self::CannotDeleteDefaultRoom => write!(f, "Cannot delete the default room"),
            Self::AuthError(msg) => write!(f, "Authentication error: {}", msg),
            Self::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            Self::Unauthorized => write!(f, "Unauthorized access"),
            Self::Forbidden => write!(f, "Forbidden: insufficient permissions"),
            Self::PermissionDenied(msg) => write!(f, "Permission denied: {}", msg),
            Self::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            Self::SystemError(msg) => write!(f, "System error: {}", msg),
            Self::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            Self::NotImplemented(msg) => write!(f, "Not implemented: {}", msg),
            Self::RegistrationError(msg) => write!(f, "Registration error: {}", msg),
            Self::NotFound(msg) => write!(f, "Not found: {}", msg),
            Self::ConflictError(msg) => write!(f, "Conflict error: {}", msg),
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

// Converting from serde_json::Error
impl From<serde_json::Error> for RustySocksError {
    fn from(err: serde_json::Error) -> Self {
        RustySocksError::MessageParseError(format!("JSON error: {}", err))
    }
}

// Converting from std::io::Error
impl From<std::io::Error> for RustySocksError {
    fn from(err: std::io::Error) -> Self {
        RustySocksError::SystemError(format!("IO error: {}", err))
    }
}

// Generic result type for RustySocks
pub type Result<T> = std::result::Result<T, RustySocksError>;
