use std::collections::HashSet;

use cookie::SameSite;

/// Configuration for the BFF instance
#[derive(Clone, Debug)]
pub struct BffConfig {
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

    /// Base path for the BFF endpoints
    pub base_path: String,

    /// Allowed proxy destinations
    pub allowed_proxy_destinations: HashSet<String>,

    /// Path to the static files
    pub static_file_path: Option<String>,

    /// CORS origin
    pub cors_origin: Option<String>,
}

impl Default for BffConfig {
    fn default() -> Self {
        Self {
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
            session_max_age: 86400, // 24 hours
            base_path: "/baffao".to_string(),
            allowed_proxy_destinations: HashSet::new(),
            static_file_path: None,
            cors_origin: None,
        }
    }
}
