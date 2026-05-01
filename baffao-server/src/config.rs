use std::collections::HashSet;
use std::fs;
use std::path::Path;

use config::{Config, ConfigError, File};
use cookie::SameSite;
use serde::{Deserialize, Serialize};

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server type (bff or tmi)
    #[serde(default = "default_server_type")]
    pub server_type: String,

    /// Server port
    #[serde(default = "default_port")]
    pub port: u16,

    /// OAuth client ID
    pub client_id: String,

    /// OAuth client secret
    pub client_secret: String,

    /// OAuth authorization endpoint URL
    pub auth_url: String,

    /// OAuth token endpoint URL
    pub token_url: String,

    /// OAuth redirect URL
    pub redirect_url: String,

    /// Default scopes to request
    #[serde(default)]
    pub default_scopes: Vec<String>,

    /// Session cookie name
    #[serde(default = "default_session_cookie_name")]
    pub session_cookie_name: String,

    /// Session cookie domain
    #[serde(default)]
    pub session_cookie_domain: Option<String>,

    /// Session cookie path
    #[serde(default = "default_session_cookie_path")]
    pub session_cookie_path: String,

    /// Whether the session cookie is secure (HTTPS only)
    #[serde(default = "default_session_cookie_secure")]
    pub session_cookie_secure: bool,

    /// Whether the session cookie is HTTP only
    #[serde(default = "default_session_cookie_http_only")]
    pub session_cookie_http_only: bool,

    /// SameSite attribute of the session cookie (strict, lax, or none)
    #[serde(default = "default_session_cookie_same_site")]
    pub session_cookie_same_site: String,

    /// Maximum age of the session in seconds
    #[serde(default = "default_session_max_age")]
    pub session_max_age: u64,

    /// Base path for the server endpoints
    #[serde(default = "default_base_path")]
    pub base_path: String,

    /// Allowed proxy destinations (BFF only)
    #[serde(default)]
    pub allowed_proxy_destinations: HashSet<String>,

    /// Path to the static files
    #[serde(default)]
    pub static_file_path: Option<String>,

    /// CORS origin
    #[serde(default)]
    pub cors_origin: Option<String>,

    /// Access token lifetime in seconds (TMI only)
    #[serde(default = "default_access_token_lifetime")]
    pub access_token_lifetime: u64,
}

impl ServerConfig {
    /// Loads the configuration from a file
    pub fn from_file(path: Option<&str>) -> Result<Self, ConfigError> {
        let config = Config::builder()
            // Add in the current environment file
            .add_source(File::with_name(path.unwrap_or("config/default")))
            // Load environment variables (prefixed with BAFFAO_)
            .add_source(config::Environment::with_prefix("BAFFAO").separator("__"))
            .build()?;

        // Deserialize the config
        config.try_deserialize()
    }

    /// Creates a default configuration
    pub fn default() -> Self {
        Self {
            server_type: default_server_type(),
            port: default_port(),
            client_id: "".to_string(),
            client_secret: "".to_string(),
            auth_url: "".to_string(),
            token_url: "".to_string(),
            redirect_url: "".to_string(),
            default_scopes: vec![],
            session_cookie_name: default_session_cookie_name(),
            session_cookie_domain: None,
            session_cookie_path: default_session_cookie_path(),
            session_cookie_secure: default_session_cookie_secure(),
            session_cookie_http_only: default_session_cookie_http_only(),
            session_cookie_same_site: default_session_cookie_same_site(),
            session_max_age: default_session_max_age(),
            base_path: default_base_path(),
            allowed_proxy_destinations: HashSet::new(),
            static_file_path: None,
            cors_origin: None,
            access_token_lifetime: default_access_token_lifetime(),
        }
    }
}

fn default_server_type() -> String {
    "bff".to_string()
}

fn default_port() -> u16 {
    3000
}

fn default_session_cookie_name() -> String {
    "__Host-baffao-session".to_string()
}

fn default_session_cookie_path() -> String {
    "/".to_string()
}

fn default_session_cookie_secure() -> bool {
    true
}

fn default_session_cookie_http_only() -> bool {
    true
}

fn default_session_cookie_same_site() -> String {
    "strict".to_string()
}

impl ServerConfig {
    pub fn get_same_site(&self) -> SameSite {
        match self.session_cookie_same_site.to_lowercase().as_str() {
            "lax" => SameSite::Lax,
            "none" => SameSite::None,
            _ => SameSite::Strict,
        }
    }
}

fn default_session_max_age() -> u64 {
    86400 // 24 hours
}

fn default_base_path() -> String {
    "/baffao".to_string()
}

fn default_access_token_lifetime() -> u64 {
    3600 // 1 hour
}
