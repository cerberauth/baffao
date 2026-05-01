use std::sync::Arc;

use baffao_core::auth::OAuthClient;
use baffao_core::csrf::CsrfManager;
use baffao_core::session::{CookieConfig, SessionManager};
use baffao_core::token::TokenManager;

use crate::config::TmiConfig;

/// Shared state for the TMI instance
#[derive(Clone)]
pub struct TmiState<S, T>
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    /// TMI configuration
    pub config: TmiConfig,

    /// Session manager
    pub session_manager: S,

    /// Token manager
    pub token_manager: T,

    /// CSRF manager
    pub csrf_manager: Arc<CsrfManager>,

    /// OAuth client
    pub oauth_client: OAuthClient,

    /// Cookie configuration
    pub cookie_config: CookieConfig,
}
