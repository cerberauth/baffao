use anyhow::Error;
use openidconnect::{
    core::CoreClient, reqwest::async_http_client, AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, JsonWebKeySet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenUrl, UserInfoUrl
};
use reqwest::Url;

use super::{AccessToken, OAuthConfig};

pub struct OpenIDConnectClient {
    config: OAuthConfig,
    client: CoreClient,
}

impl Clone for OpenIDConnectClient {
    fn clone(&self) -> Self {
        OpenIDConnectClient {
            config: self.config.clone(),
            client: self.client.clone(),
        }
    }
}

impl OpenIDConnectClient {
    pub fn new(config: OAuthConfig) -> Result<Self, Error> {
        let redirect_uri = RedirectUrl::new(config.authorization_redirect_uri)?;
        let auth_url = AuthUrl::new(config.authorization_endpoint)?;
        let issuer = IssuerUrl::new(config.issuer)?;
        let token_endpoint =
            TokenUrl::new(config.token_endpoint)?;
        let user_info_endpoint = if config.userinfo_endpoint.is_some() {
            Some(UserInfoUrl::new(config.userinfo_endpoint.unwrap())?)
        } else {
            None
        };
        if (config.jwks_uri.is_some() && config.jwks_uri.as_ref().unwrap().is_empty())
            || (config.default_scopes.is_some() && config.default_scopes.as_ref().unwrap().is_empty())
        {
            return Err(Error::msg("Invalid configuration"));
        }
        let jwks = if config.jwks_uri.is_some() {
            Some(JsonWebKeySet::fetch(config.jwks_uri.unwrap())?)
        } else {
            None
        };

        let client = CoreClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret)),
            issuer,
            auth_url,
            Some(token_endpoint),
            user_info_endpoint,
            jwks,
        )
        .set_auth_type(AuthType::RequestBody)
        .set_redirect_uri(redirect_uri);

        Ok(Self { config, client })
    }

    pub fn from_provider_metadata(&self) -> Result<Self, Error> {
        CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret)),
        );

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
    ) -> Result<AccessToken, Error> {
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

    pub async fn refresh_token(&self, refresh_token: String) -> Result<AccessToken, Error> {
        let response = self
            .client
            .exchange_refresh_token(&RefreshToken::new(refresh_token))
            .request_async(async_http_client)
            .await;
        if let Err(e) = response {
            if e.to_string().contains("invalid_grant") {
                return Err(Error::msg("Invalid refresh token"));
            } else if e.to_string().contains("invalid_client") {
                return Err(Error::msg("Invalid client"));
            }

            return Err(e.into());
        }

        Ok(response.unwrap())
    }
}
