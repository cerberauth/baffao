use anyhow::{Context, Error};
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    reqwest::async_http_client,
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    RedirectUrl, Scope, StandardTokenResponse, TokenUrl,
};
use reqwest::Url;

use super::OAuthConfig;

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
    pub fn new(config: OAuthConfig) -> Result<Self, Error> {
        let redirect_uri = RedirectUrl::new(config.authorization_redirect_uri.clone())?;
        let auth_url = AuthUrl::new(config.authorization_url.clone())?;
        let token_url = TokenUrl::new(config.token_url.clone())?;

        let client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            auth_url,
            Some(token_url),
        )
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_uri(redirect_uri);

        Ok(Self { config, client })
    }

    pub fn get_authorization_url(&self, scope: Vec<String>) -> (Url, CsrfToken) {
        let mut request = self.client.authorize_url(CsrfToken::new_random);
        if !scope.is_empty() {
            request = request.add_scope(Scope::new(scope.join(" ")));
        }

        return request.url();
    }

    pub async fn exchange_code(
        &self,
        code: String,
        csrf_token: String,
        state: String,
    ) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, Error> {
        if state != csrf_token {
            return Err(anyhow::anyhow!("Invalid state"));
        }

        let code = AuthorizationCode::new(code);
        let token = self
            .client
            .exchange_code(code)
            .request_async(async_http_client)
            .await
            .context("Failed to exchange code")?;

        Ok(token)
    }
}
