pub use client::OAuthClient;
mod client;

use serde::Deserialize;

#[derive(Deserialize, Clone)]
#[allow(unused)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub metadata_url: Option<String>,
    pub authorization_redirect_uri: String,
    pub authorization_url: String,
    pub token_url: String,
    pub userinfo_url: Option<String>,
    pub redirect_uri: Option<String>,
}
