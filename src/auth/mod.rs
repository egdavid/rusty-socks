//! Authentication and authorization module

pub mod token;
pub mod user;

// Re-export main components
pub use token::{Claims, TokenManager};
pub use user::{User, UserRole, Permission};