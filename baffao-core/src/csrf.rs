//! CSRF (Cross-Site Request Forgery) protection mechanisms.
//!
//! This module provides functionality for protecting against CSRF attacks,
//! including token generation, validation, and storage.

use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{BaffaoError, BaffaoResult};

/// Size of the random CSRF token in bytes
const CSRF_TOKEN_SIZE: usize = 32;
/// Default CSRF token expiration time in seconds
const DEFAULT_EXPIRY_SECONDS: u64 = 3600; // 1 hour

/// CSRF token with associated metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CsrfToken {
    /// The actual token value
    pub token: String,
    /// When the token was created
    pub created_at: u64,
    /// When the token expires
    pub expires_at: u64,
}

impl CsrfToken {
    /// Creates a new CSRF token with the given expiration time
    pub fn new(expiry: Option<Duration>) -> Self {
        let mut token_bytes = [0u8; CSRF_TOKEN_SIZE];
        OsRng.fill_bytes(&mut token_bytes);

        let token = URL_SAFE_NO_PAD.encode(token_bytes);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expiry_seconds = expiry
            .map(|d| d.as_secs())
            .unwrap_or(DEFAULT_EXPIRY_SECONDS);

        Self {
            token,
            created_at: now,
            expires_at: now + expiry_seconds,
        }
    }

    /// Checks if the token is expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.expires_at <= now
    }
}

/// CSRF protection manager
#[derive(Clone)]
pub struct CsrfManager {
    /// Secret key for signing tokens
    secret: Vec<u8>,
    /// Store of issued tokens
    tokens: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, CsrfToken>>>,
}

impl CsrfManager {
    /// Creates a new CSRF manager with the given secret
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            tokens: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }
    
    /// Creates a new CSRF manager with a random secret
    pub fn new_with_random_secret() -> Self {
        let mut secret = vec![0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self {
            secret,
            tokens: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }
    
    /// Generates a new CSRF token and stores it
    pub async fn generate_token(&self, expiry: Option<Duration>, context: Option<&str>) -> BaffaoResult<CsrfToken> {
        let token = CsrfToken::new(expiry);
        
        // Store the token with context if provided
        let mut tokens = self.tokens.lock().await;
        let key = if let Some(ctx) = context {
            format!("{}:{}", ctx, token.token)
        } else {
            token.token.clone()
        };
        
        tokens.insert(key, token.clone());
        
        // Clean up expired tokens occasionally (1 in 100 chance)
        if rand::random::<u8>() < 3 {
            self.cleanup_tokens(&mut tokens);
        }
        
        Ok(token)
    }
    
    /// Validates a CSRF token
    pub fn validate_token(&self, token: &str, expected_token: &CsrfToken) -> BaffaoResult<()> {
        if expected_token.is_expired() {
            return Err(BaffaoError::CsrfTokenExpired);
        }
        
        if token != expected_token.token {
            return Err(BaffaoError::InvalidCsrfToken);
        }
        
        Ok(())
    }
    
    /// Validates a CSRF token from the store
    pub async fn validate_stored_token(&self, token: &str, context: Option<&str>) -> BaffaoResult<()> {
        let mut tokens = self.tokens.lock().await;
        
        // Get the key based on context
        let key = if let Some(ctx) = context {
            format!("{}:{}", ctx, token)
        } else {
            token.to_string()
        };
        
        // Check if the token exists
        let stored_token = tokens.get(&key).cloned();
        
        match stored_token {
            Some(token) => {
                // Check if the token has expired
                if token.is_expired() {
                    tokens.remove(&key);
                    return Err(BaffaoError::CsrfTokenExpired);
                }
                
                // Remove the token to prevent reuse
                tokens.remove(&key);
                Ok(())
            }
            None => Err(BaffaoError::InvalidCsrfToken),
        }
    }
    
    /// Validates a token from a header and removes it
    pub async fn validate_token_header(&self, headers: &http::HeaderMap, header_name: &str) -> BaffaoResult<()> {
        let token = headers.get(header_name)
            .and_then(|h| h.to_str().ok())
            .ok_or(BaffaoError::InvalidCsrfToken)?;
            
        self.validate_stored_token(token, None).await
    }
    
    /// Cleans up expired tokens
    fn cleanup_tokens(&self, tokens: &mut std::collections::HashMap<String, CsrfToken>) {
        tokens.retain(|_, token| !token.is_expired());
    }
    
    /// Manually trigger cleanup of expired tokens
    pub async fn cleanup(&self) -> BaffaoResult<()> {
        let mut tokens = self.tokens.lock().await;
        self.cleanup_tokens(&mut tokens);
        Ok(())
    }

    /// Encodes a CSRF token for storage in a cookie
    pub fn encode_token(&self, token: &CsrfToken) -> BaffaoResult<String> {
        // Serialize the token
        let token_json =
            serde_json::to_string(token).map_err(|e| BaffaoError::Serialization(e.to_string()))?;

        // Create an HMAC of the token
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .map_err(|_| BaffaoError::CryptoError("Failed to create HMAC".to_string()))?;

        mac.update(token_json.as_bytes());
        let hmac = mac.finalize().into_bytes();

        // Encode the token and HMAC
        let combined = [token_json.as_bytes(), b".", hmac.as_slice()].concat();

        Ok(URL_SAFE_NO_PAD.encode(combined))
    }

    /// Decodes a CSRF token from a cookie
    pub fn decode_token(&self, encoded: &str) -> BaffaoResult<CsrfToken> {
        // Decode the combined token and HMAC
        let combined = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| BaffaoError::Decoding(e.to_string()))?;

        // Split the token and HMAC
        let parts: Vec<&[u8]> = combined.split(|&b| b == b'.').collect();
        if parts.len() != 2 {
            return Err(BaffaoError::InvalidCsrfToken);
        }

        let token_json = parts[0];
        let hmac_bytes = parts[1];

        // Verify the HMAC
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .map_err(|_| BaffaoError::CryptoError("Failed to create HMAC".to_string()))?;

        mac.update(token_json);
        mac.verify_slice(hmac_bytes)
            .map_err(|_| BaffaoError::InvalidCsrfToken)?;

        // Deserialize the token
        let token: CsrfToken = serde_json::from_slice(token_json)
            .map_err(|e| BaffaoError::Deserialization(e.to_string()))?;

        if token.is_expired() {
            return Err(BaffaoError::CsrfTokenExpired);
        }

        Ok(token)
    }
}
