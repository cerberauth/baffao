//! OAuth 2.0 authentication implementation and utilities.
//!
//! This module provides functionality for implementing OAuth 2.0 Authorization Code 
//! flow with PKCE as recommended by the OAuth 2.0 for Browser-Based Apps specification.

use std::collections::HashMap;
use std::time::Duration;

use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken as OAuth2RefreshToken, Scope, TokenUrl,
};
use oauth2::basic::BasicClient;
use oauth2::{reqwest::async_http_client, AuthorizationRequest, TokenResponse};
use oauth2::basic::BasicTokenResponse;

use crate::pkce::{CodeChallenge, CodeChallengeMethod};
use crate::oauth_state::{OAuthState, OAuthStateManager};
use crate::auth_server::AuthServerValidator;
use url::Url;

use crate::error::{BaffaoError, BaffaoResult};
use crate::token::{AccessToken, RefreshToken};

/// OAuth client configuration
#[derive(Clone, Debug)]
pub struct OAuthClientConfig {
    /// Client ID for the OAuth client
    pub client_id: String,
    /// Client secret for confidential clients
    pub client_secret: Option<String>,
    /// Authorization endpoint URL
    pub auth_url: String,
    /// Token endpoint URL
    pub token_url: String,
    /// Redirect URL for the OAuth flow
    pub redirect_url: String,
    /// Default scopes to request
    pub default_scopes: Vec<String>,
    /// State parameter expiration in seconds (defaults to 600)
    pub state_expiry: Option<Duration>,
    /// Issuer URL for validating authorization server
    pub issuer: Option<String>,
}

/// Handles OAuth 2.0 authentication flows.
#[derive(Clone)]
pub struct OAuthClient {
    client: BasicClient,
    config: OAuthClientConfig,
    state_manager: std::sync::Arc<OAuthStateManager>,
    auth_server_validator: Option<std::sync::Arc<AuthServerValidator>>,
}

/// Data needed to start an authorization flow.
#[derive(Clone, Debug)]
pub struct AuthorizationFlow {
    /// The URL to redirect the user to
    pub auth_url: Url,
    /// PKCE code verifier to be used when exchanging the code
    pub pkce_verifier: String,
    /// CSRF token to verify the callback
    pub csrf_token: String,
    /// Code challenge method used
    pub code_challenge_method: String,
}

/// Authentication response containing tokens from a successful flow
#[derive(Clone, Debug)]
pub struct AuthResponse {
    /// Access token
    pub access_token: AccessToken,
    /// Optional refresh token
    pub refresh_token: Option<RefreshToken>,
}

impl OAuthClient {
    /// Creates a new OAuthClient with the provided configuration.
    pub fn new(config: OAuthClientConfig) -> BaffaoResult<Self> {
        let auth_url = AuthUrl::new(config.auth_url.clone())
            .map_err(|_| BaffaoError::InvalidUrl("auth_url".to_string()))?;
        
        let token_url = TokenUrl::new(config.token_url.clone())
            .map_err(|_| BaffaoError::InvalidUrl("token_url".to_string()))?;
        
        let redirect_url = RedirectUrl::new(config.redirect_url.clone())
            .map_err(|_| BaffaoError::InvalidUrl("redirect_url".to_string()))?;

        let client = if let Some(secret) = &config.client_secret {
            BasicClient::new(
                ClientId::new(config.client_id.clone()),
                Some(ClientSecret::new(secret.clone())),
                auth_url,
                Some(token_url),
            )
        } else {
            BasicClient::new(
                ClientId::new(config.client_id.clone()),
                None,
                auth_url,
                Some(token_url),
            )
        }
        .set_redirect_uri(redirect_url);
        
        // Create a new OAuth state manager
        let state_manager = std::sync::Arc::new(OAuthStateManager::new_with_random_secret());

        Ok(Self { 
            client, 
            config, 
            state_manager,
            auth_server_validator: None,
        })
    }
    
    /// Creates a new OAuthClient with the provided configuration and state manager.
    pub fn with_state_manager(
        config: OAuthClientConfig,
        state_manager: std::sync::Arc<OAuthStateManager>,
    ) -> BaffaoResult<Self> {
        let auth_url = AuthUrl::new(config.auth_url.clone())
            .map_err(|_| BaffaoError::InvalidUrl("auth_url".to_string()))?;
        
        let token_url = TokenUrl::new(config.token_url.clone())
            .map_err(|_| BaffaoError::InvalidUrl("token_url".to_string()))?;
        
        let redirect_url = RedirectUrl::new(config.redirect_url.clone())
            .map_err(|_| BaffaoError::InvalidUrl("redirect_url".to_string()))?;

        let client = if let Some(secret) = &config.client_secret {
            BasicClient::new(
                ClientId::new(config.client_id.clone()),
                Some(ClientSecret::new(secret.clone())),
                auth_url,
                Some(token_url),
            )
        } else {
            BasicClient::new(
                ClientId::new(config.client_id.clone()),
                None,
                auth_url,
                Some(token_url),
            )
        }
        .set_redirect_uri(redirect_url);

        // Create an auth server validator if issuer is provided
        let auth_server_validator = if config.issuer.is_some() {
            Some(std::sync::Arc::new(AuthServerValidator::new(None)))
        } else {
            None
        };

        Ok(Self { 
            client, 
            config, 
            state_manager,
            auth_server_validator,
        })
    }
    
    /// Creates a new OAuthClient with the provided configuration and validators.
    pub fn with_validators(
        config: OAuthClientConfig,
        state_manager: std::sync::Arc<OAuthStateManager>,
        auth_server_validator: std::sync::Arc<AuthServerValidator>,
    ) -> BaffaoResult<Self> {
        let auth_url = AuthUrl::new(config.auth_url.clone())
            .map_err(|_| BaffaoError::InvalidUrl("auth_url".to_string()))?;
        
        let token_url = TokenUrl::new(config.token_url.clone())
            .map_err(|_| BaffaoError::InvalidUrl("token_url".to_string()))?;
        
        let redirect_url = RedirectUrl::new(config.redirect_url.clone())
            .map_err(|_| BaffaoError::InvalidUrl("redirect_url".to_string()))?;

        let client = if let Some(secret) = &config.client_secret {
            BasicClient::new(
                ClientId::new(config.client_id.clone()),
                Some(ClientSecret::new(secret.clone())),
                auth_url,
                Some(token_url),
            )
        } else {
            BasicClient::new(
                ClientId::new(config.client_id.clone()),
                None,
                auth_url,
                Some(token_url),
            )
        }
        .set_redirect_uri(redirect_url);

        Ok(Self { 
            client, 
            config, 
            state_manager,
            auth_server_validator: Some(auth_server_validator),
        })
    }

    /// Initiates an OAuth 2.0 Authorization Code flow with PKCE.
    pub async fn start_authorization_flow(
        &self, 
        additional_scopes: Option<Vec<String>>,
        additional_parameters: Option<HashMap<String, String>>,
    ) -> BaffaoResult<AuthorizationFlow> {
        if let (Some(validator), Some(issuer)) = (&self.auth_server_validator, &self.config.issuer) {
            validator.validate_authorization_endpoint(issuer, &self.config.auth_url).await?;
            validator.validate_token_endpoint(issuer, &self.config.token_url).await?;
        }
        let pkce = CodeChallenge::new_s256();
        
        let pkce_challenge = oauth2::PkceCodeChallenge::from_code_verifier_sha256(
            &oauth2::PkceCodeVerifier::new(pkce.verifier.clone())
        );
        
        let mut scopes = self.config.default_scopes.clone();
        if let Some(additional) = additional_scopes {
            scopes.extend(additional);
        }
        
        let mut auth_request = self.client
            .authorize_url(CsrfToken::new_random)
            .set_pkce_challenge(pkce_challenge);
            
        for scope in scopes {
            auth_request = auth_request.add_scope(Scope::new(scope));
        }
        
        let (auth_url, _csrf_token) = auth_request.url();
        
        let mut params = additional_parameters.unwrap_or_default();
        
        params.insert("pkce_verifier".to_string(), pkce.verifier.clone());
        params.insert("code_challenge_method".to_string(), "S256".to_string());
        
        let (state, oauth_state) = self.state_manager.generate_state(self.config.state_expiry, Some(params))?;
        
        self.state_manager.save_state(&state, oauth_state.clone()).await?;
        
        Ok(AuthorizationFlow {
            auth_url,
            pkce_verifier: pkce.verifier,
            csrf_token: state,
            code_challenge_method: "S256".to_string(),
        })
    }

    /// Exchanges an authorization code for tokens.
    pub async fn exchange_code(
        &self, 
        code: String, 
        state: String,
    ) -> BaffaoResult<AuthResponse> {
        if let (Some(validator), Some(issuer)) = (&self.auth_server_validator, &self.config.issuer) {
            validator.validate_token_endpoint(issuer, &self.config.token_url).await?;
        }
        let oauth_state = self.state_manager.validate_state(&state).await?;
        
        let pkce_verifier = oauth_state
            .get_parameter("pkce_verifier")
            .ok_or_else(|| BaffaoError::PkceVerificationError("PKCE verifier not found in state".to_string()))?
            .clone();
            
        if pkce_verifier.trim().is_empty() {
            return Err(BaffaoError::PkceVerificationError("PKCE verifier cannot be empty".to_string()));
        }
        
        if !pkce_verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(BaffaoError::PkceVerificationError("PKCE verifier contains invalid characters".to_string()));
        }
        
        let token_result = self.client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(async_http_client)
            .await
            .map_err(|e| BaffaoError::OAuthExchange(e.to_string()))?;
        
        self.handle_token_response(token_result)
    }
    
    /// Exchanges an authorization code using directly provided PKCE verifier.
    /// This method is less secure than using the state parameter validation.
    pub async fn exchange_code_with_verifier(
        &self, 
        code: String, 
        pkce_verifier: String,
    ) -> BaffaoResult<AuthResponse> {
        // Verify the PKCE verifier format before exchange
        if pkce_verifier.trim().is_empty() {
            return Err(BaffaoError::PkceVerificationError("PKCE verifier cannot be empty".to_string()));
        }
        
        // Ensure the PKCE verifier is properly URL safe base64 encoded
        if !pkce_verifier.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(BaffaoError::PkceVerificationError("PKCE verifier contains invalid characters".to_string()));
        }
        
        let token_result = self.client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
            .request_async(async_http_client)
            .await
            .map_err(|e| BaffaoError::OAuthExchange(e.to_string()))?;
        
        self.handle_token_response(token_result)
    }

    /// Refreshes an access token using a refresh token.
    pub async fn refresh_token(&self, refresh_token: &str) -> BaffaoResult<AuthResponse> {
        // Validate the authorization server if an issuer is provided
        if let (Some(validator), Some(issuer)) = (&self.auth_server_validator, &self.config.issuer) {
            // Validate the token endpoint
            validator.validate_token_endpoint(issuer, &self.config.token_url).await?;
        }
        
        let token_result = self.client
            .exchange_refresh_token(&OAuth2RefreshToken::new(refresh_token.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| BaffaoError::OAuthRefresh(e.to_string()))?;
        
        self.handle_token_response(token_result)
    }
    
    /// Converts an OAuth token response into our internal representation
    fn handle_token_response(&self, token_response: BasicTokenResponse) -> BaffaoResult<AuthResponse> {
        let access_token = AccessToken::new(
            token_response.access_token().secret().clone(),
            token_response.expires_in(),
            token_response.scopes().map(|scopes| {
                scopes.iter().map(|scope| scope.to_string()).collect()
            }),
        );
        
        let refresh_token = token_response.refresh_token().map(|token| {
            RefreshToken::new(token.secret().clone())
        });
        
        Ok(AuthResponse {
            access_token,
            refresh_token,
        })
    }

    /// Returns the internal basic client.
    pub fn client(&self) -> &BasicClient {
        &self.client
    }

    /// Returns the client ID.
    pub fn client_id(&self) -> &ClientId {
        self.client.client_id()
    }

    /// Returns the client secret if available.
    pub fn client_secret(&self) -> Option<&String> {
        self.config.client_secret.as_ref()
    }
}
