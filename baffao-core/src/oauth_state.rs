//! OAuth 2.0 state parameter validation
//!
//! This module provides functionality for creating and validating OAuth 2.0 state
//! parameters to prevent CSRF attacks.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{BaffaoError, BaffaoResult};

/// Default expiration time for state parameters in seconds
const DEFAULT_STATE_EXPIRY_SECONDS: u64 = 600; // 10 minutes

/// OAuth state with additional parameters and validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthState {
    /// Random nonce for uniqueness
    pub nonce: String,
    /// Timestamp when the state was created
    pub created_at: u64,
    /// Timestamp when the state expires
    pub expires_at: u64,
    /// Additional parameters to associate with the state
    pub parameters: HashMap<String, String>,
}

impl OAuthState {
    /// Creates a new OAuth state
    pub fn new(expiry: Option<Duration>, parameters: Option<HashMap<String, String>>) -> Self {
        // Generate a random nonce
        let mut nonce_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);

        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Calculate expiry time
        let expiry_seconds = expiry
            .map(|d| d.as_secs())
            .unwrap_or(DEFAULT_STATE_EXPIRY_SECONDS);

        Self {
            nonce,
            created_at: now,
            expires_at: now + expiry_seconds,
            parameters: parameters.unwrap_or_default(),
        }
    }

    /// Checks if the state has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.expires_at <= now
    }

    /// Adds a parameter to the state
    pub fn add_parameter(&mut self, key: &str, value: &str) {
        self.parameters.insert(key.to_string(), value.to_string());
    }

    /// Gets a parameter from the state
    pub fn get_parameter(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }
}

/// Storage and management for OAuth state parameters
pub struct OAuthStateManager {
    /// Secret key for signing states
    secret: Vec<u8>,
    /// Cache of state values
    states: tokio::sync::Mutex<HashMap<String, OAuthState>>,
}

impl OAuthStateManager {
    /// Creates a new OAuth state manager with the given secret
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            states: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Creates a new OAuth state manager with a random secret
    pub fn new_with_random_secret() -> Self {
        let mut secret = vec![0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Self::new(&secret)
    }

    /// Generates a new state parameter
    pub fn generate_state(
        &self,
        expiry: Option<Duration>,
        parameters: Option<HashMap<String, String>>,
    ) -> BaffaoResult<(String, OAuthState)> {
        let state = OAuthState::new(expiry, parameters);
        let encoded = self.encode_state(&state)?;
        Ok((encoded, state))
    }

    /// Encodes a state for storage and transmission
    fn encode_state(&self, state: &OAuthState) -> BaffaoResult<String> {
        // Serialize the state
        let state_json = serde_json::to_string(state)
            .map_err(|e| BaffaoError::Serialization(e.to_string()))?;

        // Create an HMAC of the state
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .map_err(|_| BaffaoError::CryptoError("Failed to create HMAC".to_string()))?;

        mac.update(state_json.as_bytes());
        let hmac = mac.finalize().into_bytes();

        // Encode the state and HMAC
        let combined = [state_json.as_bytes(), b".", hmac.as_slice()].concat();

        Ok(URL_SAFE_NO_PAD.encode(combined))
    }

    /// Decodes a state parameter
    fn decode_state(&self, encoded: &str) -> BaffaoResult<OAuthState> {
        // Decode the combined state and HMAC
        let combined = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| BaffaoError::Decoding(e.to_string()))?;

        // Split the state and HMAC
        let parts: Vec<&[u8]> = combined.split(|&b| b == b'.').collect();
        if parts.len() != 2 {
            return Err(BaffaoError::InvalidOAuthState);
        }

        let state_json = parts[0];
        let hmac_bytes = parts[1];

        // Verify the HMAC
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.secret)
            .map_err(|_| BaffaoError::CryptoError("Failed to create HMAC".to_string()))?;

        mac.update(state_json);
        mac.verify_slice(hmac_bytes)
            .map_err(|_| BaffaoError::InvalidOAuthState)?;

        // Deserialize the state
        let state: OAuthState = serde_json::from_slice(state_json)
            .map_err(|e| BaffaoError::Deserialization(e.to_string()))?;

        if state.is_expired() {
            return Err(BaffaoError::InvalidOAuthState);
        }

        Ok(state)
    }

    /// Saves a state to the internal cache
    pub async fn save_state(&self, encoded: &str, state: OAuthState) -> BaffaoResult<()> {
        let mut states = self.states.lock().await;
        states.insert(encoded.to_string(), state);
        Ok(())
    }

    /// Gets a state from the internal cache
    pub async fn get_state(&self, encoded: &str) -> BaffaoResult<Option<OAuthState>> {
        let states = self.states.lock().await;
        Ok(states.get(encoded).cloned())
    }

    /// Removes a state from the internal cache
    pub async fn remove_state(&self, encoded: &str) -> BaffaoResult<()> {
        let mut states = self.states.lock().await;
        states.remove(encoded);
        Ok(())
    }

    /// Validates a state parameter
    pub async fn validate_state(&self, encoded: &str) -> BaffaoResult<OAuthState> {
        // First try to get from the cache
        if let Some(state) = self.get_state(encoded).await? {
            if !state.is_expired() {
                // Remove from cache to prevent reuse
                self.remove_state(encoded).await?;
                return Ok(state);
            } else {
                // Remove expired state
                self.remove_state(encoded).await?;
                return Err(BaffaoError::InvalidOAuthState);
            }
        }

        // If not in cache, try to decode
        let state = self.decode_state(encoded)?;
        
        // State is valid, remove from cache to prevent reuse
        self.remove_state(encoded).await?;
        
        Ok(state)
    }

    /// Cleans up expired states
    pub async fn cleanup(&self) -> BaffaoResult<()> {
        let mut states = self.states.lock().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        states.retain(|_, state| !state.is_expired());

        Ok(())
    }
}