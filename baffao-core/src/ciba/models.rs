//! Models for CIBA operations.

use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::BaffaoResult;

/// Authentication request status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthStatus {
    /// The authentication request is pending.
    Pending,

    /// The authentication request was approved by the user.
    Approved,

    /// The authentication request was denied by the user.
    Denied,

    /// The authentication request expired.
    Expired,

    /// The authentication request was cancelled.
    Cancelled,
}

impl ToString for AuthStatus {
    fn to_string(&self) -> String {
        match self {
            AuthStatus::Pending => "pending".to_string(),
            AuthStatus::Approved => "approved".to_string(),
            AuthStatus::Denied => "denied".to_string(),
            AuthStatus::Expired => "expired".to_string(),
            AuthStatus::Cancelled => "cancelled".to_string(),
        }
    }
}

impl AuthStatus {
    /// Create an AuthStatus from a string.
    pub fn from_string(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "denied" => Some(Self::Denied),
            "expired" => Some(Self::Expired),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// CIBA authentication request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationRequest {
    /// Unique identifier for the authentication request.
    pub id: String,

    /// Identifier for the user to be authenticated.
    pub login_hint: String,

    /// Optional binding message to be displayed to the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_message: Option<String>,

    /// Requested scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Client ID making the request.
    pub client_id: String,

    /// Request created time.
    pub created_at: DateTime<Utc>,

    /// Request expiry time.
    pub expires_at: DateTime<Utc>,

    /// Current status of the authentication request.
    pub status: AuthStatus,

    /// Optional ACR (Authentication Context Class Reference) values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr_values: Option<String>,

    /// Optional user code for additional verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_code: Option<String>,

    /// Optional requested expiry for the issued tokens.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_expiry: Option<i64>,
}

impl AuthenticationRequest {
    /// Create a new authentication request.
    pub fn new(
        login_hint: String,
        binding_message: Option<String>,
        scope: Option<String>,
        client_id: String,
        expiry_seconds: Option<u64>,
        acr_values: Option<String>,
        user_code: Option<String>,
        requested_expiry: Option<i64>,
    ) -> Self {
        let created_at = Utc::now();
        let expires_at =
            created_at + chrono::Duration::seconds(expiry_seconds.unwrap_or(300) as i64);

        Self {
            id: Uuid::new_v4().to_string(),
            login_hint,
            binding_message,
            scope,
            client_id,
            created_at,
            expires_at,
            status: AuthStatus::Pending,
            acr_values,
            user_code,
            requested_expiry,
        }
    }

    /// Check if the authentication request is expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }

    /// Get the time until expiry.
    pub fn time_until_expiry(&self) -> Option<Duration> {
        let now = Utc::now();
        if self.expires_at <= now {
            None
        } else {
            self.expires_at.signed_duration_since(now).to_std().ok()
        }
    }
}

/// CIBA authentication response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationResponse {
    /// Authentication request identifier.
    pub auth_req_id: String,

    /// Interval in seconds the client should wait between polling requests.
    pub interval: u64,

    /// Expiry time of the authentication request.
    pub expires_in: u64,
}

/// CIBA token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The access token.
    pub access_token: String,

    /// The token type (e.g., "Bearer").
    pub token_type: String,

    /// Time in seconds until the access token expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,

    /// The refresh token (if provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Granted scopes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// ID token (for OpenID Connect).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
}
