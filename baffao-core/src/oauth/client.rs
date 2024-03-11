use std::time::Duration;

use anyhow::Context;
use oauth2::{
    basic::{BasicClient, BasicTokenType}, reqwest::async_http_client, AccessToken, AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, RefreshToken, Scope, StandardErrorResponse, TokenResponse, TokenUrl
};
use reqwest::Url;

use crate::settings::OAuthConfig;

#[derive(Debug)]
pub struct OAuthClient {
    config: OAuthConfig,
    client: BasicClient,
}

impl Clone for OAuthClient {
    fn clone(&self) -> Self {
        OAuthClient {
            config: self.config.clone(),
            client: self.client.clone(),
        }
    }
}

impl OAuthClient {
    pub fn new(config: OAuthConfig) -> Self {
        let client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            AuthUrl::new(config.authorization_url.clone()).unwrap(),
            Some(TokenUrl::new(config.token_url.clone()).unwrap()),
        )
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_uri(RedirectUrl::new(config.authorization_redirect_uri.clone()).unwrap());

        Self { config, client }
    }

    pub fn get_authorization_url(&self, scope: Vec<String>) -> (Url, CsrfToken) {
        let mut request = self.client.authorize_url(CsrfToken::new_random);
        if !scope.is_empty() {
            request = request.add_scope(Scope::new(scope.join(" ")));
        }

        let (auth_url, csrf_token) = request.url();
        (auth_url, csrf_token)
    }

    pub async fn exchange_code(
        &self,
        code: String,
        csrf_token: String,
        state: String,
    ) -> Result<(AccessToken, Option<RefreshToken>, Option<Duration>), anyhow::Error> {
        if state != csrf_token {
            return Err(anyhow::anyhow!("Invalid state"));
        }

        let code = AuthorizationCode::new(code);
        let token = self.client
            .exchange_code(code)
            .request_async(async_http_client)
            .await
            .context("Failed to exchange code")?;

        Ok((token.access_token().clone(), token.refresh_token().cloned(), token.expires_in()))
    }
}
