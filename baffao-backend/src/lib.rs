/*!
# Baffao Backend

Unified implementation of Backend For Frontend (BFF) and Token-Mediating Backend (TMI) patterns
for OAuth 2.0 browser-based applications.

This crate provides both patterns with a common API, allowing you to choose the appropriate
pattern for your application's security and architectural requirements.

## Patterns

- **Backend For Frontend (BFF)**: The backend handles all OAuth responsibilities and API proxying.
- **Token-Mediating Backend (TMI)**: The backend manages tokens but allows direct resource server access.

## Features

- OAuth 2.0 Authorization Code flow with PKCE
- Secure session management with cookie-based authentication
- CSRF protection
- Token binding with DPoP
- Scope validation and least privilege
- Rate limiting
- Token revocation
- Authorization server validation
- JWK validation for token verification
*/

use std::sync::Arc;

use baffao_core::prelude::*;
use baffao_core::session::{CookieConfig, SessionManager};
use baffao_core::token::TokenManager;
use baffao_core::csrf::CsrfManager;

mod config;
mod handlers;
mod middleware;
mod proxy;
mod routes;
mod state;

pub use config::{BackendConfig, BackendType};
pub use state::BackendState;
pub use routes::create_router;

/// Version of the crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Builder for configuring and creating a Backend instance
pub struct BackendBuilder<S, T>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    config: BackendConfig,
    session_manager: Option<S>,
    token_manager: Option<T>,
    csrf_manager: Option<Arc<CsrfManager>>,
    auth_server_validator: Option<Arc<AuthServerValidator>>,
    jwk_validator: Option<Arc<JwkValidator>>,
    rate_limiter: Option<Arc<RateLimiter>>,
}

impl<S, T> BackendBuilder<S, T>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    /// Creates a new BackendBuilder with the given configuration
    pub fn new(config: BackendConfig) -> Self {
        Self {
            config,
            session_manager: None,
            token_manager: None,
            csrf_manager: None,
            auth_server_validator: None,
            jwk_validator: None,
            rate_limiter: None,
        }
    }

    /// Sets the session manager
    pub fn with_session_manager(mut self, session_manager: S) -> Self {
        self.session_manager = Some(session_manager);
        self
    }

    /// Sets the token manager
    pub fn with_token_manager(mut self, token_manager: T) -> Self {
        self.token_manager = Some(token_manager);
        self
    }

    /// Sets the CSRF manager
    pub fn with_csrf_manager(mut self, csrf_manager: Arc<CsrfManager>) -> Self {
        self.csrf_manager = Some(csrf_manager);
        self
    }

    /// Sets the authorization server validator
    pub fn with_auth_server_validator(mut self, validator: Arc<AuthServerValidator>) -> Self {
        self.auth_server_validator = Some(validator);
        self
    }

    /// Sets the JWK validator
    pub fn with_jwk_validator(mut self, validator: Arc<JwkValidator>) -> Self {
        self.jwk_validator = Some(validator);
        self
    }

    /// Sets the rate limiter
    pub fn with_rate_limiter(mut self, rate_limiter: Arc<RateLimiter>) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Builds the Backend state
    pub fn build(self) -> BaffaoResult<BackendState<S, T>> {
        let session_manager = self.session_manager
            .ok_or_else(|| BaffaoError::Configuration("Session manager is required".to_string()))?;
            
        let token_manager = self.token_manager
            .ok_or_else(|| BaffaoError::Configuration("Token manager is required".to_string()))?;
            
        let csrf_manager = self.csrf_manager.unwrap_or_else(|| {
            Arc::new(CsrfManager::new_with_random_secret())
        });

        let auth_server_validator = if self.config.issuer.is_some() {
            Some(self.auth_server_validator.unwrap_or_else(|| {
                Arc::new(AuthServerValidator::new(None))
            }))
        } else {
            self.auth_server_validator
        };

        // Configure OAuth client
        let oauth_client_config = OAuthClientConfig {
            client_id: self.config.client_id.clone(),
            client_secret: Some(self.config.client_secret.clone()),
            auth_url: self.config.auth_url.clone(),
            token_url: self.config.token_url.clone(),
            redirect_url: self.config.redirect_url.clone(),
            default_scopes: self.config.default_scopes.clone(),
            state_expiry: Some(std::time::Duration::from_secs(self.config.state_expiry_seconds)),
            issuer: self.config.issuer.clone(),
        };

        let oauth_client = OAuthClient::new(oauth_client_config)?;
        // Configure cookie
        let cookie_config = CookieConfig {
            name: self.config.session_cookie_name.clone(),
            domain: self.config.session_cookie_domain.clone(),
            path: self.config.session_cookie_path.clone(),
            secure: self.config.session_cookie_secure,
            http_only: self.config.session_cookie_http_only,
            same_site: self.config.session_cookie_same_site,
            max_age: Some(self.config.session_max_age as i64),
        };

        Ok(BackendState {
            config: self.config,
            session_manager,
            token_manager,
            csrf_manager,
            auth_server_validator,
            jwk_validator: self.jwk_validator,
            rate_limiter: self.rate_limiter,
            oauth_client,
            cookie_config,
        })
    }
}

/// Re-export commonly used items
pub mod prelude {
    pub use crate::BackendBuilder;
    pub use crate::BackendConfig;
    pub use crate::BackendState;
    pub use crate::BackendType;
    pub use crate::create_router;
    
    // Re-export core types for convenience
    pub use baffao_core::prelude::*;
}