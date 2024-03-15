pub use client::OAuthClient;
mod client;

use serde::Deserialize;

/**
 * OAuthConfig
 *
 * This struct is used to store the OAuth configuration.
 * Authorization Server Metadata: https://datatracker.ietf.org/doc/html/rfc8414
*/
#[derive(Deserialize, Clone)]
#[allow(unused)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub authorization_redirect_uri: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub redirect_uri: Option<String>,
    pub default_scopes: Option<Vec<String>>,
}
