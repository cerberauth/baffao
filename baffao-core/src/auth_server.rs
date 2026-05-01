//! OAuth 2.0 Authorization Server validation
//!
//! This module provides functionality for discovering and validating
//! OAuth 2.0 authorization servers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error::{BaffaoError, BaffaoResult};

/// Default expiration time for cached metadata in seconds
const DEFAULT_METADATA_CACHE_SECONDS: u64 = 3600; // 1 hour

/// OpenID Connect discovery document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenIDConfiguration {
    /// Issuer identifier
    pub issuer: String,
    /// Authorization endpoint
    pub authorization_endpoint: String,
    /// Token endpoint
    pub token_endpoint: String,
    /// JSON Web Key Set endpoint
    #[serde(rename = "jwks_uri")]
    pub jwks_uri: String,
    /// Supported response types
    pub response_types_supported: Vec<String>,
    /// Supported grant types
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    /// Supported subject types
    #[serde(default)]
    pub subject_types_supported: Vec<String>,
    /// Supported ID token signing algorithms
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Supported scopes
    #[serde(default)]
    pub scopes_supported: Option<Vec<String>>,
    /// Supported token endpoint auth methods
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    /// Supported claims
    #[serde(default)]
    pub claims_supported: Option<Vec<String>>,
    /// Token revocation endpoint
    #[serde(default)]
    pub revocation_endpoint: Option<String>,
    /// Token introspection endpoint
    #[serde(default)]
    pub introspection_endpoint: Option<String>,
}

/// Cached authorization server metadata
#[derive(Debug, Clone)]
struct CachedMetadata {
    /// The OpenID Configuration
    pub metadata: OpenIDConfiguration,
    /// When the metadata was fetched
    pub fetched_at: u64,
    /// When the metadata expires
    pub expires_at: u64,
}

/// Authorization server validator
#[derive(Clone)]
pub struct AuthServerValidator {
    /// HTTP client for making requests
    client: Client,
    /// Cache of authorization server metadata
    metadata_cache: Arc<tokio::sync::Mutex<HashMap<String, CachedMetadata>>>,
    /// Cache expiration time in seconds
    cache_expiry: u64,
}

impl AuthServerValidator {
    /// Creates a new authorization server validator
    pub fn new(cache_expiry: Option<u64>) -> Self {
        Self {
            client: Client::new(),
            metadata_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            cache_expiry: cache_expiry.unwrap_or(DEFAULT_METADATA_CACHE_SECONDS),
        }
    }

    /// Discovers and validates an authorization server
    pub async fn validate_server(&self, issuer: &str) -> BaffaoResult<OpenIDConfiguration> {
        // Check if we have cached metadata
        let cached = {
            let cache = self.metadata_cache.lock().await;
            cache.get(issuer).cloned()
        };

        if let Some(cached) = cached {
            // Check if the cached metadata is still valid
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if now < cached.expires_at {
                return Ok(cached.metadata);
            }
        }

        // Fetch the metadata
        let metadata = self.fetch_metadata(issuer).await?;

        // Validate the metadata
        self.validate_metadata(&metadata, issuer)?;

        // Cache the metadata
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cached = CachedMetadata {
            metadata: metadata.clone(),
            fetched_at: now,
            expires_at: now + self.cache_expiry,
        };

        let mut cache = self.metadata_cache.lock().await;
        cache.insert(issuer.to_string(), cached);

        Ok(metadata)
    }

    /// Fetches the authorization server metadata
    async fn fetch_metadata(&self, issuer: &str) -> BaffaoResult<OpenIDConfiguration> {
        // Normalize the issuer URL
        let issuer = if issuer.ends_with('/') {
            issuer.to_string()
        } else {
            format!("{}/", issuer)
        };

        // Construct the discovery URL
        let discovery_url = format!("{}/.well-known/openid-configuration", issuer);

        // Fetch the metadata
        let response = self.client
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| BaffaoError::AuthServerValidationError(format!(
                "Failed to fetch metadata: {}", e
            )))?;

        if !response.status().is_success() {
            return Err(BaffaoError::AuthServerValidationError(format!(
                "Failed to fetch metadata: HTTP {}", response.status()
            )));
        }

        // Parse the metadata
        let metadata: OpenIDConfiguration = response.json().await
            .map_err(|e| BaffaoError::AuthServerValidationError(format!(
                "Failed to parse metadata: {}", e
            )))?;

        Ok(metadata)
    }

    /// Validates the authorization server metadata
    fn validate_metadata(&self, metadata: &OpenIDConfiguration, issuer: &str) -> BaffaoResult<()> {
        // Validate the issuer
        if metadata.issuer != issuer && metadata.issuer != issuer.trim_end_matches('/') {
            return Err(BaffaoError::AuthServerValidationError(format!(
                "Issuer mismatch: expected '{}', got '{}'", issuer, metadata.issuer
            )));
        }

        // Validate required fields
        if metadata.authorization_endpoint.is_empty() {
            return Err(BaffaoError::AuthServerValidationError(
                "Missing authorization_endpoint".to_string()
            ));
        }

        if metadata.token_endpoint.is_empty() {
            return Err(BaffaoError::AuthServerValidationError(
                "Missing token_endpoint".to_string()
            ));
        }

        if metadata.jwks_uri.is_empty() {
            return Err(BaffaoError::AuthServerValidationError(
                "Missing jwks_uri".to_string()
            ));
        }

        // Validate response types
        if !metadata.response_types_supported.contains(&"code".to_string()) {
            return Err(BaffaoError::AuthServerValidationError(
                "Authorization server does not support 'code' response type".to_string()
            ));
        }

        // Validate grant types
        if metadata.grant_types_supported.is_empty() {
            // Not all servers advertise grant types
            return Ok(());
        }

        if !metadata.grant_types_supported.contains(&"authorization_code".to_string()) {
            return Err(BaffaoError::AuthServerValidationError(
                "Authorization server does not support 'authorization_code' grant type".to_string()
            ));
        }

        if !metadata.grant_types_supported.contains(&"refresh_token".to_string()) {
            return Err(BaffaoError::AuthServerValidationError(
                "Authorization server does not support 'refresh_token' grant type".to_string()
            ));
        }

        Ok(())
    }

    /// Gets the JWKS URI for an issuer
    pub async fn get_jwks_uri(&self, issuer: &str) -> BaffaoResult<String> {
        let metadata = self.validate_server(issuer).await?;
        Ok(metadata.jwks_uri)
    }

    /// Gets the token endpoint for an issuer
    pub async fn get_token_endpoint(&self, issuer: &str) -> BaffaoResult<String> {
        let metadata = self.validate_server(issuer).await?;
        Ok(metadata.token_endpoint)
    }

    /// Gets the authorization endpoint for an issuer
    pub async fn get_authorization_endpoint(&self, issuer: &str) -> BaffaoResult<String> {
        let metadata = self.validate_server(issuer).await?;
        Ok(metadata.authorization_endpoint)
    }

    /// Gets the revocation endpoint for an issuer
    pub async fn get_revocation_endpoint(&self, issuer: &str) -> BaffaoResult<Option<String>> {
        let metadata = self.validate_server(issuer).await?;
        Ok(metadata.revocation_endpoint)
    }

    /// Validates that a token endpoint belongs to the expected issuer
    pub async fn validate_token_endpoint(&self, issuer: &str, token_endpoint: &str) -> BaffaoResult<()> {
        let metadata = self.validate_server(issuer).await?;
        if metadata.token_endpoint != token_endpoint {
            return Err(BaffaoError::AuthServerValidationError(format!(
                "Token endpoint mismatch: expected '{}', got '{}'", 
                metadata.token_endpoint, token_endpoint
            )));
        }
        Ok(())
    }

    /// Validates that an authorization endpoint belongs to the expected issuer
    pub async fn validate_authorization_endpoint(&self, issuer: &str, authorization_endpoint: &str) -> BaffaoResult<()> {
        let metadata = self.validate_server(issuer).await?;
        if metadata.authorization_endpoint != authorization_endpoint {
            return Err(BaffaoError::AuthServerValidationError(format!(
                "Authorization endpoint mismatch: expected '{}', got '{}'", 
                metadata.authorization_endpoint, authorization_endpoint
            )));
        }
        Ok(())
    }

    /// Clears the metadata cache
    pub async fn clear_cache(&self) -> BaffaoResult<()> {
        let mut cache = self.metadata_cache.lock().await;
        cache.clear();
        Ok(())
    }
}