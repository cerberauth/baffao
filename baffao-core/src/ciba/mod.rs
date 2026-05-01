//! CIBA (Client Initiated Backchannel Authentication) implementation.
//!
//! This module implements the CIBA specification (OAuth 2.0 Client Initiated Backchannel Authentication Flow),
//! which allows clients to initiate the authentication flow with the authorization server without direct
//! involvement of the user-agent (browser).

mod client;
mod error;
mod models;
mod store;
mod verification;

pub use client::CibaClient;
pub use error::{CibaError, CibaResult};
pub use models::{AuthenticationRequest, AuthenticationResponse, TokenResponse, AuthStatus};
pub use store::{CibaRequestStore, InMemoryCibaRequestStore};
pub use verification::CibaVerifier;

#[cfg(test)]
mod tests;