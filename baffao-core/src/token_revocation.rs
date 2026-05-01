//! Token manager with revocation support
//!
//! This module provides a token manager decorator that adds support for
//! revoking tokens with the authorization server.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{BaffaoError, BaffaoResult};
use crate::revocation::RevocationClient;
use crate::token::{AccessToken, RefreshToken, TokenManager};

/// Token manager with revocation support
pub struct RevocableTokenManager<T: TokenManager> {
    /// Inner token manager
    inner: Arc<T>,
    /// Revocation client
    revocation_client: Arc<RevocationClient>,
}

impl<T: TokenManager> RevocableTokenManager<T> {
    /// Creates a new revocable token manager
    pub fn new(inner: T, revocation_client: RevocationClient) -> Self {
        Self {
            inner: Arc::new(inner),
            revocation_client: Arc::new(revocation_client),
        }
    }
}

#[async_trait]
impl<T: TokenManager + Sync + Send> TokenManager for RevocableTokenManager<T> {
    async fn store_access_token(&self, user_id: &str, token: AccessToken) -> BaffaoResult<()> {
        self.inner.store_access_token(user_id, token).await
    }

    async fn get_access_token(&self, user_id: &str) -> BaffaoResult<Option<AccessToken>> {
        self.inner.get_access_token(user_id).await
    }

    async fn store_refresh_token(&self, user_id: &str, token: RefreshToken) -> BaffaoResult<()> {
        self.inner.store_refresh_token(user_id, token).await
    }

    async fn get_refresh_token(&self, user_id: &str) -> BaffaoResult<Option<RefreshToken>> {
        self.inner.get_refresh_token(user_id).await
    }

    async fn revoke_tokens(&self, user_id: &str) -> BaffaoResult<()> {
        // Get tokens to revoke
        let access_token = self.inner.get_access_token(user_id).await?;
        let refresh_token = self.inner.get_refresh_token(user_id).await?;

        // Revoke refresh token first (which may revoke all tokens derived from it)
        if let Some(token) = refresh_token {
            match self.revocation_client.revoke_refresh_token(&token.token).await {
                Ok(_) => {
                    // Successfully revoked, now remove from storage
                    self.inner.revoke_tokens(user_id).await?;
                }
                Err(e) => {
                    // Log the error but continue trying to revoke access token
                    tracing::warn!("Failed to revoke refresh token: {}", e);
                    
                    // Still remove from storage
                    self.inner.revoke_tokens(user_id).await?;
                }
            }
        } else if let Some(token) = access_token {
            // No refresh token, try to revoke the access token
            match self.revocation_client.revoke_access_token(&token.token).await {
                Ok(_) => {
                    // Successfully revoked, now remove from storage
                    self.inner.revoke_tokens(user_id).await?;
                }
                Err(e) => {
                    // Log the error but continue
                    tracing::warn!("Failed to revoke access token: {}", e);
                    
                    // Still remove from storage
                    self.inner.revoke_tokens(user_id).await?;
                }
            }
        } else {
            // No tokens to revoke, just remove from storage
            self.inner.revoke_tokens(user_id).await?;
        }

        Ok(())
    }

    async fn get_access_token_for_scope(&self, user_id: &str, required_scopes: &[String]) -> BaffaoResult<Option<AccessToken>> {
        self.inner.get_access_token_for_scope(user_id, required_scopes).await
    }
}