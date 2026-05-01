/*!
# Baffao Core

Core functionality for OAuth 2.0 Backend For Frontend (BFF) and Token-Mediating Backend implementations.

This crate provides the foundation for both the BFF and Token-Mediating Backend patterns,
including OAuth 2.0 flows, token management, session handling, and more.

## Features

- OAuth 2.0 Authorization Code flow with PKCE
- Token management (access tokens, refresh tokens)
- Session interfaces
- Error types and handling
- Security utilities
*/

// Re-export oauth2 crate for consistent version usage
pub use oauth2;

pub mod auth;
pub mod auth_server;
pub mod ciba;
pub mod csrf;
pub mod dpop;
pub mod error;
pub mod jwk;
pub mod oauth_state;
pub mod pkce;
pub mod rate_limit;
pub mod revocation;
pub mod security_policy;
pub mod session;
pub mod storage;
pub mod telemetry;
pub mod token;
pub mod token_revocation;
pub mod token_scope;
pub mod utils;

/// Re-export commonly used items
pub mod prelude {
    pub use crate::auth::*;
    pub use crate::auth_server::{AuthServerValidator, OpenIDConfiguration};
    pub use crate::ciba::{CibaClient, CibaVerifier, CibaRequestStore, InMemoryCibaRequestStore};
    pub use crate::ciba::{AuthenticationRequest, AuthenticationResponse, AuthStatus};
    pub use crate::ciba::{CibaError, CibaResult};
    pub use crate::dpop::{DPoPKeyPair, DPoPVerifier, DPoPClientExt};
    pub use crate::error::{BaffaoError, BaffaoResult};
    pub use crate::jwk::{JwkValidator, JwkValidatorConfig, JwtClaims};
    pub use crate::oauth_state::{OAuthState, OAuthStateManager};
    pub use crate::pkce::{CodeChallenge, CodeChallengeMethod, PkceStore};
    pub use crate::rate_limit::{RateLimiter, RateLimitedTokenManager, RateLimiterConfig};
    pub use crate::revocation::{RevocationClient, RevocationConfig};
    pub use crate::security_policy::{
        TokenLifetimePolicy, TokenLifetimeManager,
        IpAccessPolicy, IpAccessManager, IpAccessRule, IpAccessAction,
        AuditLogger, AuditEvent, AuditLevel, FileAuditLogger, ConsoleAuditLogger,
    };
    pub use crate::session::SessionManager;
    pub use crate::storage::{StorageError, StorageResult};
    #[cfg(feature = "postgres")]
    pub use crate::storage::PostgresBackend;
    #[cfg(feature = "redis")]
    pub use crate::storage::RedisBackend;
    pub use crate::telemetry::{TelemetryConfig, LoggingConfig, MetricsConfig, TracingConfig};
    pub use crate::telemetry::{setup_logging, setup_metrics, setup_tracing};
    pub use crate::telemetry::{record_token_operation, record_auth_operation};
    pub use crate::token::{AccessToken, RefreshToken, TokenManager};
    pub use crate::token_revocation::RevocableTokenManager;
    pub use crate::token_scope::ScopedTokenManager;
    pub use crate::utils::*;
}

/// Version of the crate
pub const VERSION: &str = env!("CARGO_PKG_VERSION");