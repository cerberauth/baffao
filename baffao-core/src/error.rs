//! Error types for the Baffao library.

use std::fmt;

#[derive(Debug)]
pub enum BaffaoError {
    /// OAuth client error
    OAuth(String),

    /// OAuth exchange error
    OAuthExchange(String),

    /// OAuth refresh error
    OAuthRefresh(String),

    /// Configuration error
    Configuration(String),

    /// Session error
    Session(String),

    /// Invalid session
    InvalidSession,

    /// Session expired
    SessionExpired,

    /// Unauthorized
    Unauthorized,

    /// Forbidden
    Forbidden,

    /// Proxy error
    Proxy(String),

    /// Token error
    Token(String),

    /// CSRF error
    Csrf(String),

    /// Authorization error
    Authorization(String),

    /// Rate limit error
    RateLimit(String),

    /// Network error
    Network(String),

    /// Storage error
    Storage(String),

    /// Token validation error
    TokenValidation(String),

    /// JWK validation error
    JwkValidationError(String),

    /// Rate limit exceeded error
    RateLimitExceeded(String),

    /// Internal error
    Internal(String),

    /// Crypto error
    CryptoError(String),

    /// Invalid DPoP proof
    InvalidDpopProof(String),

    /// Serialization error
    Serialization(String),

    /// Deserialization error
    Deserialization(String),

    /// Decoding error
    Decoding(String),

    /// Invalid OAuth state
    InvalidOAuthState,

    /// PKCE verification error
    PkceVerificationError(String),

    /// Validation error
    ValidationError(String),

    /// Not found error
    NotFound(String),

    /// I/O error
    Io(String),

    /// Scope validation error
    ScopeValidationError(String),

    /// Invalid URL
    InvalidUrl(String),

    /// Auth server validation error
    AuthServerValidationError(String),

    /// Revocation error
    RevocationError(String),

    /// CSRF token expired
    CsrfTokenExpired,

    /// Invalid CSRF token
    InvalidCsrfToken,

    /// Generic error
    Other(String),
}

impl fmt::Display for BaffaoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaffaoError::OAuth(msg) => write!(f, "OAuth error: {}", msg),
            BaffaoError::OAuthExchange(msg) => write!(f, "OAuth exchange error: {}", msg),
            BaffaoError::OAuthRefresh(msg) => write!(f, "OAuth refresh error: {}", msg),
            BaffaoError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            BaffaoError::Session(msg) => write!(f, "Session error: {}", msg),
            BaffaoError::InvalidSession => write!(f, "Invalid session"),
            BaffaoError::SessionExpired => write!(f, "Session expired"),
            BaffaoError::Unauthorized => write!(f, "Unauthorized"),
            BaffaoError::Forbidden => write!(f, "Forbidden"),
            BaffaoError::Proxy(msg) => write!(f, "Proxy error: {}", msg),
            BaffaoError::Token(msg) => write!(f, "Token error: {}", msg),
            BaffaoError::Csrf(msg) => write!(f, "CSRF error: {}", msg),
            BaffaoError::Authorization(msg) => write!(f, "Authorization error: {}", msg),
            BaffaoError::RateLimit(msg) => write!(f, "Rate limit error: {}", msg),
            BaffaoError::Network(msg) => write!(f, "Network error: {}", msg),
            BaffaoError::Storage(msg) => write!(f, "Storage error: {}", msg),
            BaffaoError::TokenValidation(msg) => write!(f, "Token validation error: {}", msg),
            BaffaoError::JwkValidationError(msg) => write!(f, "JWK validation error: {}", msg),
            BaffaoError::RateLimitExceeded(msg) => write!(f, "Rate limit exceeded: {}", msg),
            BaffaoError::Internal(msg) => write!(f, "Internal error: {}", msg),
            BaffaoError::CryptoError(msg) => write!(f, "Crypto error: {}", msg),
            BaffaoError::InvalidDpopProof(msg) => write!(f, "Invalid DPoP proof: {}", msg),
            BaffaoError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            BaffaoError::Deserialization(msg) => write!(f, "Deserialization error: {}", msg),
            BaffaoError::Decoding(msg) => write!(f, "Decoding error: {}", msg),
            BaffaoError::InvalidOAuthState => write!(f, "Invalid OAuth state"),
            BaffaoError::PkceVerificationError(msg) => write!(f, "PKCE verification error: {}", msg),
            BaffaoError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            BaffaoError::NotFound(msg) => write!(f, "Not found: {}", msg),
            BaffaoError::Io(msg) => write!(f, "I/O error: {}", msg),
            BaffaoError::ScopeValidationError(msg) => write!(f, "Scope validation error: {}", msg),
            BaffaoError::InvalidUrl(msg) => write!(f, "Invalid URL: {}", msg),
            BaffaoError::AuthServerValidationError(msg) => write!(f, "Auth server validation error: {}", msg),
            BaffaoError::RevocationError(msg) => write!(f, "Revocation error: {}", msg),
            BaffaoError::CsrfTokenExpired => write!(f, "CSRF token expired"),
            BaffaoError::InvalidCsrfToken => write!(f, "Invalid CSRF token"),
            BaffaoError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl BaffaoError {
    /// Returns the HTTP status code associated with this error
    pub fn status_code(&self) -> http::StatusCode {
        match self {
            BaffaoError::InvalidSession | BaffaoError::Unauthorized | BaffaoError::SessionExpired => {
                http::StatusCode::UNAUTHORIZED
            }
            BaffaoError::Forbidden => http::StatusCode::FORBIDDEN,
            BaffaoError::NotFound(_) => http::StatusCode::NOT_FOUND,
            BaffaoError::RateLimit(_) | BaffaoError::RateLimitExceeded(_) => {
                http::StatusCode::TOO_MANY_REQUESTS
            }
            BaffaoError::ValidationError(_)
            | BaffaoError::InvalidCsrfToken
            | BaffaoError::CsrfTokenExpired
            | BaffaoError::PkceVerificationError(_)
            | BaffaoError::ScopeValidationError(_) => http::StatusCode::BAD_REQUEST,
            _ => http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl std::error::Error for BaffaoError {}

impl
    From<
        oauth2::RequestTokenError<
            oauth2::reqwest::Error<reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    > for BaffaoError
{
    fn from(
        err: oauth2::RequestTokenError<
            oauth2::reqwest::Error<reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    ) -> Self {
        BaffaoError::OAuth(format!("Token request error: {}", err))
    }
}

impl From<reqwest::Error> for BaffaoError {
    fn from(err: reqwest::Error) -> Self {
        BaffaoError::Network(format!("HTTP request error: {}", err))
    }
}

impl From<serde_json::Error> for BaffaoError {
    fn from(err: serde_json::Error) -> Self {
        BaffaoError::Other(format!("JSON error: {}", err))
    }
}

impl From<std::io::Error> for BaffaoError {
    fn from(err: std::io::Error) -> Self {
        BaffaoError::Other(format!("I/O error: {}", err))
    }
}

/// Result type for Baffao operations.
pub type BaffaoResult<T> = Result<T, BaffaoError>;
