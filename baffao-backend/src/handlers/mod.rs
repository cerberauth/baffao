pub mod auth;
pub mod csrf;

/// BFF-specific handlers
pub mod bff;
/// TMI-specific handlers
pub mod tmi;

// Re-export handlers for ease of use
pub use auth::*;
pub use csrf::*;