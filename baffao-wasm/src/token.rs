use serde::{Deserialize, Serialize};

/// Access token with metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessToken {
    /// The access token string
    pub access_token: String,
    /// The token type (usually "Bearer")
    pub token_type: String,
    /// Time until the token expires in seconds
    pub expires_in: Option<u64>,
    /// Scopes associated with the token
    pub scope: Option<Vec<String>>,
}

/// Request for an access token
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    /// Requested scopes
    pub scopes: Option<Vec<String>>,
}

/// Response containing an access token
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token string
    pub access_token: String,
    /// The token type (usually "Bearer")
    pub token_type: String,
    /// Time until the token expires in seconds
    pub expires_in: Option<u64>,
    /// Scopes associated with the token
    pub scope: Option<Vec<String>>,
}
