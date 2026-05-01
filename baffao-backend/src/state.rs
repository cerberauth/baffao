use std::sync::Arc;

use baffao_core::auth::OAuthClient;
use baffao_core::auth_server::AuthServerValidator;
use baffao_core::csrf::CsrfManager;
use baffao_core::jwk::JwkValidator;
use baffao_core::rate_limit::RateLimiter;
use baffao_core::session::{CookieConfig, SessionManager};
use baffao_core::token::TokenManager;

use crate::config::BackendConfig;

/// Shared state for the Backend instance
#[derive(Clone)]
pub struct BackendState<S, T>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    /// Backend configuration
    pub config: BackendConfig,

    /// Session manager
    pub session_manager: S,

    /// Token manager
    pub token_manager: T,

    /// CSRF manager
    pub csrf_manager: Arc<CsrfManager>,

    /// Authorization server validator
    pub auth_server_validator: Option<Arc<AuthServerValidator>>,

    /// JWK validator
    pub jwk_validator: Option<Arc<JwkValidator>>,

    /// Rate limiter
    pub rate_limiter: Option<Arc<RateLimiter>>,

    /// OAuth client
    pub oauth_client: OAuthClient,

    /// Cookie configuration
    pub cookie_config: CookieConfig,
}
