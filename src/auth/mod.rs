//! Authentication and authorization module

pub mod provider;
pub mod token;
pub mod user;

// Re-export main components
pub use provider::{AuthManager, AuthManagerBuilder, AuthProvider, AuthResult, AuthenticatedUser};
pub use token::{Claims, TokenManager};
pub use user::{Permission, User, UserRole};
