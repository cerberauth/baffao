//! Telemetry and monitoring functionality.
//!
//! This module provides telemetry features such as metrics, tracing, and logging
//! for monitoring and debugging Baffao applications.

mod config;
pub mod logging;
#[cfg(feature = "telemetry")]
pub mod metrics;
#[cfg(feature = "telemetry")]
pub mod tracing;

pub use config::{TelemetryConfig, LoggingConfig, MetricsConfig, TracingConfig};
pub use logging::setup_logging;

/// Metrics types for token operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenOperation {
    /// Access token issued
    Issue,
    /// Access token refreshed
    Refresh,
    /// Access token validated
    Validate,
    /// Access token revoked
    Revoke,
}

impl TokenOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            TokenOperation::Issue => "issue",
            TokenOperation::Refresh => "refresh",
            TokenOperation::Validate => "validate",
            TokenOperation::Revoke => "revoke",
        }
    }
}

/// Metrics types for authentication operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthOperation {
    /// Authorization request initiated
    AuthRequest,
    /// Authorization code issued
    CodeIssued,
    /// Authorization code exchanged
    CodeExchange,
    /// PKCE challenge verified
    PkceVerify,
    /// CSRF token verified
    CsrfVerify,
    /// DPoP proof verified
    DPoPVerify,
}

impl AuthOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthOperation::AuthRequest => "auth_request",
            AuthOperation::CodeIssued => "code_issued",
            AuthOperation::CodeExchange => "code_exchange",
            AuthOperation::PkceVerify => "pkce_verify",
            AuthOperation::CsrfVerify => "csrf_verify",
            AuthOperation::DPoPVerify => "dpop_verify",
        }
    }
}

#[cfg(feature = "telemetry")]
pub use metrics::{setup_metrics, MetricsRegistry, record_token_operation, record_auth_operation};
#[cfg(feature = "telemetry")]
pub use tracing::{setup_tracing, trace_request, trace_token_flow};

#[cfg(not(feature = "telemetry"))]
pub fn setup_metrics(_: &MetricsConfig) -> crate::error::BaffaoResult<()> { Ok(()) }
#[cfg(not(feature = "telemetry"))]
pub fn setup_tracing(_: &TracingConfig) -> crate::error::BaffaoResult<()> { Ok(()) }
#[cfg(not(feature = "telemetry"))]
pub fn record_token_operation(_: TokenOperation, _: &str, _: bool, _: Option<std::time::Duration>) {}
#[cfg(not(feature = "telemetry"))]
pub fn record_auth_operation(_: AuthOperation, _: &str, _: bool, _: Option<std::time::Duration>) {}