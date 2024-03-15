use anyhow::{Context, Error};
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    reqwest::async_http_client,
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardTokenResponse, TokenUrl,
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
        let redirect_uri = RedirectUrl::new(config.authorization_redirect_uri.clone())
            .context("Failed to parse redirect uri")?;
        let auth_url = AuthUrl::new(config.authorization_endpoint.clone())
            .context("Failed to parse authorization url")?;
        let token_endpoint =
            TokenUrl::new(config.token_endpoint.clone()).context("Failed to parse token url")?;

        let client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            auth_url,
            Some(token_endpoint),
        )
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_uri(redirect_uri);

        Ok(Self { config, client })
    }

    pub fn build_authorization_endpoint(
        &self,
        scope: Option<Vec<String>>,
    ) -> (Url, CsrfToken, PkceCodeVerifier) {
        let scopes =
            scope.unwrap_or_else(|| self.config.default_scopes.clone().unwrap_or_default());
        let (pkce_code_challenge, pkce_code_verifier) = PkceCodeChallenge::new_random_sha256();

        let (url, csrf_token) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes.iter().map(|s| Scope::new(s.clone())))
            .set_pkce_challenge(pkce_code_challenge)
            .url();

        (url, csrf_token, pkce_code_verifier)
    }

    pub async fn exchange_code(
        &self,
        code: String,
        pkce_verifier: String,
    ) -> Result<StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>, Error> {
        let response = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(async_http_client)
            .await;
        if let Err(e) = response {
            if e.to_string().contains("invalid_grant") {
                return Err(Error::msg("Invalid authorization code"));
            } else if e.to_string().contains("invalid_request") {
                return Err(Error::msg("Invalid PKCE verifier"));
            } else if e.to_string().contains("invalid_client") {
                return Err(Error::msg("Invalid client"));
            }

            return Err(e.into());
        }

        Ok(response.unwrap())
    }
}
