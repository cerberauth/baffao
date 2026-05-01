//! JWK (JSON Web Key) validation for token verification
//!
//! This module provides functionality for fetching and validating JWKs
//! from an authorization server.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, jwk::JwkSet};
use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::auth_server::AuthServerValidator;
use crate::error::{BaffaoError, BaffaoResult};

/// Default expiration time for cached JWKs in seconds
const DEFAULT_JWKS_CACHE_SECONDS: u64 = 3600; // 1 hour

/// JWT header for extracting key ID
#[derive(Debug, Deserialize, Serialize)]
struct JwtHeader {
    /// Key ID
    #[serde(rename = "kid")]
    key_id: Option<String>,
    /// Algorithm
    #[serde(rename = "alg")]
    algorithm: String,
}

/// JWT claims for validation
#[derive(Debug, Deserialize, Serialize)]
pub struct JwtClaims {
    /// Issuer
    #[serde(rename = "iss")]
    pub issuer: String,
    /// Subject
    #[serde(rename = "sub")]
    pub subject: String,
    /// Audience
    #[serde(rename = "aud")]
    pub audience: String,
    /// Expiration time
    #[serde(rename = "exp")]
    pub expiration: u64,
    /// Issued at
    #[serde(rename = "iat")]
    pub issued_at: u64,
    /// Token ID
    #[serde(rename = "jti")]
    pub token_id: Option<String>,
    /// Other claims
    #[serde(flatten)]
    pub other: HashMap<String, serde_json::Value>,
}

/// JWK validation configuration
#[derive(Clone, Debug)]
pub struct JwkValidatorConfig {
    /// Issuer URL for discovering JWKS endpoint
    pub issuer: Option<String>,
    /// Explicit JWKS URI
    pub jwks_uri: Option<String>,
    /// Expected audience value(s)
    pub audience: Vec<String>,
    /// Cache expiration in seconds
    pub cache_expiry: Option<u64>,
}

/// Cached JWKs
#[derive(Debug, Clone)]
struct CachedJwks {
    /// JWK set
    jwks: JwkSet,
    /// When the JWKs were fetched
    fetched_at: u64,
    /// When the JWKs expire
    expires_at: u64,
}

/// JWK validator for verifying tokens
pub struct JwkValidator {
    /// HTTP client
    client: Client,
    /// Validator configuration
    config: JwkValidatorConfig,
    /// Cache of JWKs
    jwks_cache: Arc<tokio::sync::Mutex<HashMap<String, CachedJwks>>>,
    /// Authorization server validator
    auth_validator: Option<AuthServerValidator>,
}

impl JwkValidator {
    /// Creates a new JWK validator
    pub fn new(config: JwkValidatorConfig) -> Self {
        let auth_validator = if config.issuer.is_some() && config.jwks_uri.is_none() {
            Some(AuthServerValidator::new(None))
        } else {
            None
        };

        Self {
            client: Client::new(),
            config,
            jwks_cache: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            auth_validator,
        }
    }

    /// Gets the JWKS URI
    async fn get_jwks_uri(&self) -> BaffaoResult<String> {
        // If explicit JWKS URI is provided, use it
        if let Some(uri) = &self.config.jwks_uri {
            return Ok(uri.clone());
        }

        // Otherwise, try to discover it from the issuer
        if let Some(validator) = &self.auth_validator {
            if let Some(issuer) = &self.config.issuer {
                return validator.get_jwks_uri(issuer).await;
            }
        }

        Err(BaffaoError::JwkValidationError(
            "No JWKS URI available".to_string()
        ))
    }

    /// Fetches the JWKS from the authorization server
    async fn fetch_jwks(&self) -> BaffaoResult<JwkSet> {
        let jwks_uri = self.get_jwks_uri().await?;

        let response = self.client
            .get(&jwks_uri)
            .send()
            .await
            .map_err(|e| BaffaoError::JwkValidationError(format!(
                "Failed to fetch JWKS: {}", e
            )))?;

        if !response.status().is_success() {
            return Err(BaffaoError::JwkValidationError(format!(
                "Failed to fetch JWKS: HTTP {}", response.status()
            )));
        }

        let jwks: JwkSet = response.json().await
            .map_err(|e| BaffaoError::JwkValidationError(format!(
                "Failed to parse JWKS: {}", e
            )))?;

        Ok(jwks)
    }

    /// Gets the JWKS, fetching if necessary
    async fn get_jwks(&self) -> BaffaoResult<JwkSet> {
        let cache_key = self.get_jwks_uri().await?;
        
        // Check if we have cached JWKs
        let cached = {
            let cache = self.jwks_cache.lock().await;
            cache.get(&cache_key).cloned()
        };

        if let Some(cached) = cached {
            // Check if the cached JWKs are still valid
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if now < cached.expires_at {
                return Ok(cached.jwks);
            }
        }

        // Fetch new JWKs
        let jwks = self.fetch_jwks().await?;

        // Cache the JWKs
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let cache_expiry = self.config.cache_expiry.unwrap_or(DEFAULT_JWKS_CACHE_SECONDS);

        let cached = CachedJwks {
            jwks: jwks.clone(),
            fetched_at: now,
            expires_at: now + cache_expiry,
        };

        let mut cache = self.jwks_cache.lock().await;
        cache.insert(cache_key, cached);

        Ok(jwks)
    }

    /// Validates a JWT token
    pub async fn validate_token(&self, token: &str) -> BaffaoResult<JwtClaims> {
        // Split the token to get the header
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(BaffaoError::JwkValidationError("Invalid JWT format".to_string()));
        }

        // Decode the header
        let header_data = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| BaffaoError::JwkValidationError(format!("Invalid header: {}", e)))?;

        let header: JwtHeader = serde_json::from_slice(&header_data)
            .map_err(|e| BaffaoError::JwkValidationError(format!("Invalid header JSON: {}", e)))?;

        // Get the JWK with the matching key ID
        let jwks = self.get_jwks().await?;
        
        let jwk = if let Some(kid) = &header.key_id {
            jwks.find(kid).ok_or_else(|| {
                BaffaoError::JwkValidationError(format!("Key ID not found: {}", kid))
            })?
        } else {
            // If no key ID is specified and there's only one key, use that
            if jwks.keys.len() == 1 {
                &jwks.keys[0]
            } else {
                return Err(BaffaoError::JwkValidationError(
                    "No key ID specified and multiple keys available".to_string()
                ));
            }
        };

        // Get the decoding key
        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|e| BaffaoError::JwkValidationError(format!("Invalid JWK: {}", e)))?;

        // Determine the algorithm
        let algorithm = match header.algorithm.as_str() {
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            "ES256" => Algorithm::ES256,
            "ES384" => Algorithm::ES384,
            "HS256" => Algorithm::HS256,
            "HS384" => Algorithm::HS384,
            "HS512" => Algorithm::HS512,
            "PS256" => Algorithm::PS256,
            "PS384" => Algorithm::PS384,
            "PS512" => Algorithm::PS512,
            "EdDSA" => Algorithm::EdDSA,
            alg => return Err(BaffaoError::JwkValidationError(format!("Unsupported algorithm: {}", alg))),
        };

        // Set up validation
        let mut validation = Validation::new(algorithm);
        
        // Set expected audience
        if !self.config.audience.is_empty() {
            validation.set_audience(&self.config.audience);
        }
        
        // Set expected issuer
        if let Some(issuer) = &self.config.issuer {
            validation.set_issuer(&[issuer]);
        }
        
        // Allow for some clock skew
        validation.leeway = 60; // 60 seconds
        
        // Validate the token
        let token_data = jsonwebtoken::decode::<JwtClaims>(token, &decoding_key, &validation)
            .map_err(|e| BaffaoError::JwkValidationError(format!("Token validation failed: {}", e)))?;
            
        Ok(token_data.claims)
    }
}