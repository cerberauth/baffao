//! Error types for CIBA operations.

use std::fmt;

/// Error type for CIBA operations.
#[derive(Debug)]
pub enum CibaError {
    /// The authorization request failed.
    AuthorizationFailed(String),

    /// Configuration error.
    ConfigurationError(String),

    /// The token request failed.
    TokenRequestFailed(String),

    /// The authentication request is invalid.
    InvalidAuthenticationRequest(String),

    /// User authentication failed.
    UserAuthenticationFailed(String),

    /// Request validation error.
    ValidationError(String),

    /// Request timed out.
    Timeout(String),

    /// Network or transport error.
    NetworkError(String),

    /// Request not found.
    NotFound(String),

    /// An error occurred with the auth_req_id.
    InvalidAuthReqId(String),

    /// Client authentication failed.
    ClientAuthenticationFailed(String),

    /// The specified operation requires user interaction.
    UserInteractionRequired(String),

    /// Server error.
    ServerError(String),

    /// Storage error.
    StorageError(String),

    /// User cancelled the authentication request.
    UserCancelled(String),

    /// Expired authentication request.
    ExpiredRequest(String),

    /// Unknown error.
    Unknown(String),
}

impl fmt::Display for CibaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CibaError::AuthorizationFailed(msg) => write!(f, "Authorization failed: {}", msg),
            CibaError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            CibaError::TokenRequestFailed(msg) => write!(f, "Token request failed: {}", msg),
            CibaError::InvalidAuthenticationRequest(msg) => {
                write!(f, "Invalid authentication request: {}", msg)
            }
            CibaError::UserAuthenticationFailed(msg) => {
                write!(f, "User authentication failed: {}", msg)
            }
            CibaError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            CibaError::Timeout(msg) => write!(f, "Request timeout: {}", msg),
            CibaError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            CibaError::NotFound(msg) => write!(f, "Not found: {}", msg),
            CibaError::InvalidAuthReqId(msg) => write!(f, "Invalid auth_req_id: {}", msg),
            CibaError::ClientAuthenticationFailed(msg) => {
                write!(f, "Client authentication failed: {}", msg)
            }
            CibaError::UserInteractionRequired(msg) => {
                write!(f, "User interaction required: {}", msg)
            }
            CibaError::ServerError(msg) => write!(f, "Server error: {}", msg),
            CibaError::StorageError(msg) => write!(f, "Storage error: {}", msg),
            CibaError::UserCancelled(msg) => write!(f, "User cancelled: {}", msg),
            CibaError::ExpiredRequest(msg) => write!(f, "Expired request: {}", msg),
            CibaError::Unknown(msg) => write!(f, "Unknown error: {}", msg),
        }
    }
}

impl std::error::Error for CibaError {}

/// Result type for CIBA operations.
pub type CibaResult<T> = Result<T, CibaError>;
