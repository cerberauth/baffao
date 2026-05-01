/*!
# Baffao Backend For Frontend (BFF)

This crate implements the Backend For Frontend (BFF) pattern for OAuth 2.0 browser-based applications.
In this pattern, the BFF acts as a confidential OAuth client and handles all OAuth flows and token management.
It also proxies all API requests, attaching the appropriate access tokens.

## Features

- OAuth 2.0 Authorization Code flow with PKCE
- Secure cookie-based session management
- Token management (access tokens, refresh tokens)
- Proxy for API requests
- CSRF protection
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

pub use config::BffConfig;
pub use state::BffState;
pub use routes::create_router;

/// Version of the crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Builder for configuring and creating a BFF instance
pub struct BffBuilder<S, T>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    config: BffConfig,
    session_manager: Option<S>,
    token_manager: Option<T>,
    csrf_manager: Option<Arc<CsrfManager>>,
}

impl<S, T> BffBuilder<S, T>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    /// Creates a new BffBuilder with the given configuration
    pub fn new(config: BffConfig) -> Self {
        Self {
            config,
            session_manager: None,
            token_manager: None,
            csrf_manager: None,
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

    /// Builds the BFF state
    pub fn build(self) -> BaffaoResult<BffState<S, T>> {
        let session_manager = self.session_manager
            .ok_or_else(|| BaffaoError::Configuration("Session manager is required".to_string()))?;
            
        let token_manager = self.token_manager
            .ok_or_else(|| BaffaoError::Configuration("Token manager is required".to_string()))?;
            
        let csrf_manager = self.csrf_manager.unwrap_or_else(|| {
            Arc::new(CsrfManager::new_with_random_secret())
        });
        
        let oauth_client = baffao_core::auth::OAuthClient::new(
            baffao_core::auth::OAuthClientConfig {
                client_id: self.config.client_id,
                client_secret: Some(self.config.client_secret),
                auth_url: self.config.auth_url,
                token_url: self.config.token_url,
                redirect_url: self.config.redirect_url,
                default_scopes: self.config.default_scopes,
            },
        )?;
        
        let cookie_config = CookieConfig {
            name: self.config.session_cookie_name,
            domain: self.config.session_cookie_domain,
            path: self.config.session_cookie_path,
            secure: self.config.session_cookie_secure,
            http_only: self.config.session_cookie_http_only,
            same_site: self.config.session_cookie_same_site,
            max_age: Some(self.config.session_max_age as i64),
        };
        
        Ok(BffState {
            config: self.config,
            session_manager,
            token_manager,
            csrf_manager,
            oauth_client,
            cookie_config,
        })
    }
}

/// Re-export commonly used items
pub mod prelude {
    pub use crate::BffBuilder;
    pub use crate::BffConfig;
    pub use crate::BffState;
    pub use crate::create_router;
    
    // Re-export core types for convenience
    pub use baffao_core::prelude::*;
}