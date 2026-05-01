//! Token management for OAuth 2.0 flows.
//!
//! This module provides functionality for managing access tokens and refresh tokens,
//! including creation, validation, and storage.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{BaffaoError, BaffaoResult};

/// Represents an OAuth 2.0 access token with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// The actual token value
    pub token: String,
    /// When the token was issued
    pub issued_at: DateTime<Utc>,
    /// When the token expires
    pub expires_at: DateTime<Utc>,
    /// Scopes associated with the token
    pub scopes: Option<Vec<String>>,
}

/// Represents an OAuth 2.0 refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    /// The actual token value
    pub token: String,
    /// When the token was issued
    pub issued_at: DateTime<Utc>,
}

impl AccessToken {
    /// Creates a new access token with the provided information.
    pub fn new(
        token: String,
        expires_in: Option<Duration>,
        scopes: Option<Vec<String>>,
    ) -> Self {
        let issued_at = Utc::now();
        let expires_at = if let Some(duration) = expires_in {
            issued_at + chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::hours(1))
        } else {
            // Default to 1 hour expiration if not specified
            issued_at + chrono::Duration::hours(1)
        };

        Self {
            token,
            issued_at,
            expires_at,
            scopes,
        }
    }

    /// Checks if the access token is expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }

    /// Checks if the token has the required scopes.
    pub fn has_scopes(&self, required_scopes: &[String]) -> bool {
        if let Some(token_scopes) = &self.scopes {
            let token_scope_set: HashSet<&String> = token_scopes.iter().collect();
            required_scopes.iter().all(|scope| token_scope_set.contains(scope))
        } else {
            required_scopes.is_empty()
        }
    }
    
    /// Checks if the token has exactly the required scopes.
    /// This implements the "principle of least privilege" by ensuring the token
    /// doesn't have any unnecessary scopes.
    pub fn has_exact_scopes(&self, required_scopes: &[String]) -> bool {
        if let Some(token_scopes) = &self.scopes {
            let token_scope_set: HashSet<&String> = token_scopes.iter().collect();
            let required_scope_set: HashSet<&String> = required_scopes.iter().collect();
            
            // Check if sets are equal
            token_scope_set.len() == required_scope_set.len() && 
                token_scope_set.iter().all(|scope| required_scope_set.contains(scope))
        } else {
            required_scopes.is_empty()
        }
    }
    
    /// Gets the intersection of token scopes and required scopes.
    /// This is useful for determining which scopes are available.
    pub fn scope_intersection(&self, required_scopes: &[String]) -> Vec<String> {
        if let Some(token_scopes) = &self.scopes {
            let token_scope_set: HashSet<&String> = token_scopes.iter().collect();
            required_scopes.iter()
                .filter(|scope| token_scope_set.contains(scope))
                .map(|s| s.clone())
                .collect()
        } else {
            vec![]
        }
    }

    /// Returns the remaining time until the token expires.
    pub fn time_until_expiry(&self) -> Option<Duration> {
        let now = Utc::now();
        if self.expires_at <= now {
            None
        } else {
            self.expires_at.signed_duration_since(now).to_std().ok()
        }
    }
}

impl RefreshToken {
    /// Creates a new refresh token.
    pub fn new(token: String) -> Self {
        Self {
            token,
            issued_at: Utc::now(),
        }
    }
}

/// Trait for token storage and management.
#[async_trait]
pub trait TokenManager: Send + Sync {
    /// Stores an access token.
    async fn store_access_token(&self, user_id: &str, access_token: AccessToken) -> BaffaoResult<()>;

    /// Retrieves an access token for a user.
    async fn get_access_token(&self, user_id: &str) -> BaffaoResult<Option<AccessToken>>;

    /// Stores a refresh token.
    async fn store_refresh_token(&self, user_id: &str, refresh_token: RefreshToken) -> BaffaoResult<()>;

    /// Retrieves a refresh token for a user.
    async fn get_refresh_token(&self, user_id: &str) -> BaffaoResult<Option<RefreshToken>>;
    
    /// Revokes tokens for a user.
    async fn revoke_tokens(&self, user_id: &str) -> BaffaoResult<()>;
    
    /// Gets access token by scope requirement
    async fn get_access_token_for_scope(&self, user_id: &str, required_scopes: &[String]) -> BaffaoResult<Option<AccessToken>> {
        // Default implementation checks if the existing token has the required scopes
        let token = self.get_access_token(user_id).await?;
        if let Some(token) = token {
            if token.has_scopes(required_scopes) && !token.is_expired() {
                return Ok(Some(token));
            }
        }
        Ok(None)
    }
}

/// In-memory implementation of TokenManager for testing and simple cases.
#[derive(Default)]
pub struct InMemoryTokenManager {
    access_tokens: tokio::sync::Mutex<std::collections::HashMap<String, AccessToken>>,
    refresh_tokens: tokio::sync::Mutex<std::collections::HashMap<String, RefreshToken>>,
}

impl InMemoryTokenManager {
    /// Creates a new in-memory token manager.
    pub fn new() -> Self {
        Self {
            access_tokens: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            refresh_tokens: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait]
impl TokenManager for InMemoryTokenManager {
    async fn store_access_token(&self, user_id: &str, access_token: AccessToken) -> BaffaoResult<()> {
        let mut tokens = self.access_tokens.lock().await;
        tokens.insert(user_id.to_string(), access_token);
        Ok(())
    }

    async fn get_access_token(&self, user_id: &str) -> BaffaoResult<Option<AccessToken>> {
        let tokens = self.access_tokens.lock().await;
        Ok(tokens.get(user_id).cloned())
    }

    async fn store_refresh_token(&self, user_id: &str, refresh_token: RefreshToken) -> BaffaoResult<()> {
        let mut tokens = self.refresh_tokens.lock().await;
        tokens.insert(user_id.to_string(), refresh_token);
        Ok(())
    }

    async fn get_refresh_token(&self, user_id: &str) -> BaffaoResult<Option<RefreshToken>> {
        let tokens = self.refresh_tokens.lock().await;
        Ok(tokens.get(user_id).cloned())
    }
    
    async fn revoke_tokens(&self, user_id: &str) -> BaffaoResult<()> {
        let mut access_tokens = self.access_tokens.lock().await;
        let mut refresh_tokens = self.refresh_tokens.lock().await;
        
        access_tokens.remove(user_id);
        refresh_tokens.remove(user_id);
        
        Ok(())
    }
}