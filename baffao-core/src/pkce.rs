//! PKCE (Proof Key for Code Exchange) implementation
//!
//! This module provides functionality for implementing PKCE (RFC 7636),
//! which helps protect against authorization code interception attacks.

#[cfg(test)]
mod tests;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::error::{BaffaoError, BaffaoResult};

/// Size of the code verifier in bytes
const CODE_VERIFIER_SIZE: usize = 32;

/// PKCE code challenge method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    /// Plain code challenge method (not recommended)
    Plain,
    /// S256 code challenge method (recommended, uses SHA-256)
    S256,
}

impl CodeChallengeMethod {
    /// Returns the method as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::S256 => "S256",
        }
    }

    /// Creates a CodeChallengeMethod from a string
    pub fn from_str(method: &str) -> Option<Self> {
        match method.to_lowercase().as_str() {
            "plain" => Some(Self::Plain),
            "s256" => Some(Self::S256),
            _ => None,
        }
    }
}

impl Default for CodeChallengeMethod {
    fn default() -> Self {
        Self::S256
    }
}

/// PKCE code verifier and challenge
#[derive(Debug, Clone)]
pub struct CodeChallenge {
    /// The code verifier (secret)
    pub verifier: String,
    /// The code challenge (derived from the verifier)
    pub challenge: String,
    /// The code challenge method
    pub method: CodeChallengeMethod,
    /// Timestamp when the challenge was created
    pub created_at: u64,
}

impl CodeChallenge {
    /// Creates a new code challenge with the specified method
    pub fn new(method: CodeChallengeMethod) -> Self {
        // Generate a random code verifier
        let mut verifier_bytes = [0u8; CODE_VERIFIER_SIZE];
        OsRng.fill_bytes(&mut verifier_bytes);
        let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        // Generate the code challenge
        let challenge = match method {
            CodeChallengeMethod::Plain => verifier.clone(),
            CodeChallengeMethod::S256 => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let hash = hasher.finalize();
                URL_SAFE_NO_PAD.encode(hash)
            }
        };

        // Get the current timestamp
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            verifier,
            challenge,
            method,
            created_at,
        }
    }

    /// Creates a new code challenge with the S256 method
    pub fn new_s256() -> Self {
        Self::new(CodeChallengeMethod::S256)
    }

    /// Verifies that a code verifier matches this challenge
    pub fn verify(&self, verifier: &str, max_age: Option<Duration>) -> BaffaoResult<()> {
        // Check if the challenge has expired
        if let Some(max_age) = max_age {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let age = now - self.created_at;
            if age > max_age.as_secs() {
                return Err(BaffaoError::PkceVerificationError(
                    "PKCE challenge has expired".to_string(),
                ));
            }
        }

        // Verify that the verifier matches the challenge
        let computed_challenge = match self.method {
            CodeChallengeMethod::Plain => verifier.to_string(),
            CodeChallengeMethod::S256 => {
                let mut hasher = Sha256::new();
                hasher.update(verifier.as_bytes());
                let hash = hasher.finalize();
                URL_SAFE_NO_PAD.encode(hash)
            }
        };

        if computed_challenge != self.challenge {
            return Err(BaffaoError::PkceVerificationError(
                "PKCE verifier does not match challenge".to_string(),
            ));
        }

        Ok(())
    }
}

/// Storage for PKCE challenges
#[derive(Debug, Default)]
pub struct PkceStore {
    /// Map of code challenge -> (verifier, method, created_at)
    challenges: tokio::sync::Mutex<std::collections::HashMap<String, CodeChallenge>>,
}

impl PkceStore {
    /// Creates a new PKCE store
    pub fn new() -> Self {
        Self {
            challenges: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Stores a code challenge
    pub async fn store_challenge(&self, state: &str, challenge: CodeChallenge) -> BaffaoResult<()> {
        let mut challenges = self.challenges.lock().await;
        challenges.insert(state.to_string(), challenge);
        Ok(())
    }

    /// Retrieves a code challenge
    pub async fn get_challenge(&self, state: &str) -> BaffaoResult<Option<CodeChallenge>> {
        let challenges = self.challenges.lock().await;
        Ok(challenges.get(state).cloned())
    }

    /// Removes a code challenge
    pub async fn remove_challenge(&self, state: &str) -> BaffaoResult<()> {
        let mut challenges = self.challenges.lock().await;
        challenges.remove(state);
        Ok(())
    }

    /// Verifies a code verifier
    pub async fn verify_verifier(
        &self,
        state: &str,
        verifier: &str,
        max_age: Option<Duration>,
    ) -> BaffaoResult<()> {
        let challenge = match self.get_challenge(state).await? {
            Some(challenge) => challenge,
            None => {
                return Err(BaffaoError::PkceVerificationError(
                    "PKCE challenge not found for state".to_string(),
                ))
            }
        };

        // Verify the challenge
        let result = challenge.verify(verifier, max_age);

        // Remove the challenge to prevent reuse
        self.remove_challenge(state).await?;

        result
    }

    /// Cleans up expired challenges
    pub async fn cleanup(&self, max_age: Duration) -> BaffaoResult<()> {
        let mut challenges = self.challenges.lock().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        challenges.retain(|_, challenge| {
            let age = now - challenge.created_at;
            age <= max_age.as_secs()
        });

        Ok(())
    }
}