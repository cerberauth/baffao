use std::collections::HashSet;

use cookie::SameSite;

/// Backend type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendType {
    /// Backend For Frontend pattern
    BFF,
    /// Token-Mediating Backend pattern
    TMI,
}

/// Configuration for the Backend instance
#[derive(Clone, Debug)]
pub struct BackendConfig {
    /// Backend type (BFF or TMI)
    pub backend_type: BackendType,

    /// OAuth client ID
    pub client_id: String,

    /// OAuth client secret (required for confidential clients)
    pub client_secret: String,

    /// OAuth authorization endpoint URL
    pub auth_url: String,

    /// OAuth token endpoint URL
    pub token_url: String,

    /// OAuth redirect URL
    pub redirect_url: String,

    /// Default scopes to request
    pub default_scopes: Vec<String>,

    /// Session cookie name
    pub session_cookie_name: String,

    /// Session cookie domain
    pub session_cookie_domain: Option<String>,

    /// Session cookie path
    pub session_cookie_path: String,

    /// Whether the session cookie is secure (HTTPS only)
    pub session_cookie_secure: bool,

    /// Whether the session cookie is HTTP only
    pub session_cookie_http_only: bool,

    /// SameSite attribute of the session cookie
    pub session_cookie_same_site: SameSite,

    /// Maximum age of the session in seconds
    pub session_max_age: u64,

    /// State parameter expiration in seconds
    pub state_expiry_seconds: u64,

    /// Base path for the backend endpoints
    pub base_path: String,

    /// Allowed proxy destinations (for BFF mode)
    pub allowed_proxy_destinations: HashSet<String>,

    /// Path to the static files
    pub static_file_path: Option<String>,

    /// CORS origin
    pub cors_origin: Option<String>,

    /// Access token lifetime in seconds (for TMI mode)
    pub access_token_lifetime: Option<u64>,

    /// Issuer URL for validating the authorization server
    pub issuer: Option<String>,

    /// JWKS URI for validating tokens
    pub jwks_uri: Option<String>,
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            backend_type: BackendType::BFF,
            client_id: "".to_string(),
            client_secret: "".to_string(),
            auth_url: "".to_string(),
            token_url: "".to_string(),
            redirect_url: "".to_string(),
            default_scopes: vec![],
            session_cookie_name: "__Host-baffao-session".to_string(),
            session_cookie_domain: None,
            session_cookie_path: "/".to_string(),
            session_cookie_secure: true,
            session_cookie_http_only: true,
            session_cookie_same_site: SameSite::Strict,
            session_max_age: 86400,    // 24 hours
            state_expiry_seconds: 600, // 10 minutes
            base_path: "/baffao".to_string(),
            allowed_proxy_destinations: HashSet::new(),
            static_file_path: None,
            cors_origin: None,
            access_token_lifetime: Some(3600), // 1 hour
            issuer: None,
            jwks_uri: None,
        }
    }
}
