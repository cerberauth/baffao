//! Token revocation implementation
//!
//! This module provides functionality for revoking OAuth tokens
//! according to RFC 7009.

use std::collections::HashMap;

use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

use crate::auth_server::AuthServerValidator;
use crate::error::{BaffaoError, BaffaoResult};

/// Default token type hint for revocation
const DEFAULT_TOKEN_TYPE_HINT: &str = "refresh_token";

/// Token revocation parameters
#[derive(Debug, Serialize)]
struct RevocationParams<'a> {
    /// Client ID
    client_id: &'a str,
    /// Client secret (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    /// Token to revoke
    token: &'a str,
    /// Token type hint
    token_type_hint: &'a str,
}

/// Token revocation configuration
#[derive(Clone, Debug)]
pub struct RevocationConfig {
    /// Client ID for the OAuth client
    pub client_id: String,
    /// Client secret for confidential clients
    pub client_secret: Option<String>,
    /// Issuer URL for discovering revocation endpoint
    pub issuer: Option<String>,
    /// Explicit revocation endpoint URL
    pub revocation_url: Option<String>,
}

/// Token revocation client
pub struct RevocationClient {
    /// HTTP client
    client: Client,
    /// Client configuration
    config: RevocationConfig,
    /// Authorization server validator
    auth_validator: Option<AuthServerValidator>,
}

impl RevocationClient {
    /// Creates a new revocation client
    pub fn new(config: RevocationConfig) -> Self {
        let auth_validator = if config.issuer.is_some() && config.revocation_url.is_none() {
            Some(AuthServerValidator::new(None))
        } else {
            None
        };

        Self {
            client: Client::new(),
            config,
            auth_validator,
        }
    }

    /// Revokes a token
    pub async fn revoke_token(&self, token: &str, token_type_hint: Option<&str>) -> BaffaoResult<()> {
        // Determine the revocation endpoint
        let revocation_url = self.get_revocation_endpoint().await?;

        let params = RevocationParams {
            client_id: &self.config.client_id,
            client_secret: self.config.client_secret.as_deref(),
            token,
            token_type_hint: token_type_hint.unwrap_or(DEFAULT_TOKEN_TYPE_HINT),
        };

        // Send the revocation request
        let response = self.client
            .post(&revocation_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| BaffaoError::RevocationError(format!(
                "Failed to revoke token: {}", e
            )))?;

        // RFC 7009 says the response should be 200 OK for success
        // but some implementations return 204 No Content
        let status = response.status();
        if status != StatusCode::OK && status != StatusCode::NO_CONTENT {
            let error_text = response.text().await.unwrap_or_default();
            return Err(BaffaoError::RevocationError(format!(
                "Token revocation failed with status {}: {}", status, error_text
            )));
        }

        Ok(())
    }

    /// Revokes a refresh token
    pub async fn revoke_refresh_token(&self, token: &str) -> BaffaoResult<()> {
        self.revoke_token(token, Some("refresh_token")).await
    }

    /// Revokes an access token
    pub async fn revoke_access_token(&self, token: &str) -> BaffaoResult<()> {
        self.revoke_token(token, Some("access_token")).await
    }

    /// Gets the revocation endpoint URL
    async fn get_revocation_endpoint(&self) -> BaffaoResult<String> {
        // If explicit revocation URL is provided, use it
        if let Some(url) = &self.config.revocation_url {
            return Ok(url.clone());
        }

        // Otherwise, try to discover it from the issuer
        if let Some(validator) = &self.auth_validator {
            if let Some(issuer) = &self.config.issuer {
                if let Some(endpoint) = validator.get_revocation_endpoint(issuer).await? {
                    return Ok(endpoint);
                }
            }
        }

        Err(BaffaoError::RevocationError(
            "No revocation endpoint available".to_string()
        ))
    }
}