//! Token scope validation and management
//!
//! This module provides functionality for validating and managing token scopes,
//! implementing the principle of least privilege.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{BaffaoError, BaffaoResult};
use crate::token::{AccessToken, RefreshToken, TokenManager};

/// Token scope validator to enforce the principle of least privilege
#[derive(Clone)]
pub struct ScopedTokenManager<T: TokenManager> {
    /// The inner token manager
    inner: Arc<T>,
    /// Default allowed scopes
    allowed_scopes: HashSet<String>,
    /// Scope mapping rules (key -> set of allowed values)
    scope_mappings: HashMap<String, HashSet<String>>,
}

impl<T: TokenManager> ScopedTokenManager<T> {
    /// Creates a new scoped token manager
    pub fn new(inner: T, allowed_scopes: Vec<String>) -> Self {
        let allowed_set = allowed_scopes.into_iter().collect();
        Self {
            inner: Arc::new(inner),
            allowed_scopes: allowed_set,
            scope_mappings: HashMap::new(),
        }
    }

    /// Adds a scope mapping rule
    pub fn add_scope_mapping(&mut self, key: String, values: Vec<String>) -> &mut Self {
        self.scope_mappings.insert(key, values.into_iter().collect());
        self
    }

    /// Validates scopes against allowed scopes and mappings
    pub fn validate_scopes(&self, scopes: &[String]) -> BaffaoResult<()> {
        // Check against allowed scopes
        for scope in scopes {
            if !self.allowed_scopes.contains(scope) {
                let mapping_found = self.scope_mappings.iter().any(|(key, values)| {
                    if scope.starts_with(key) {
                        let suffix = &scope[key.len()..];
                        values.contains(suffix)
                    } else {
                        false
                    }
                });

                if !mapping_found {
                    return Err(BaffaoError::ScopeValidationError(format!(
                        "Scope '{}' is not allowed", scope
                    )));
                }
            }
        }

        Ok(())
    }

    /// Filters scopes based on allowed scopes and mappings
    pub fn filter_scopes(&self, scopes: &[String]) -> Vec<String> {
        scopes.iter().filter(|scope| {
            if self.allowed_scopes.contains(*scope) {
                return true;
            }

            self.scope_mappings.iter().any(|(key, values)| {
                if scope.starts_with(key) {
                    let suffix = &scope[key.len()..];
                    values.contains(suffix)
                } else {
                    false
                }
            })
        }).cloned().collect()
    }
}

#[async_trait]
impl<T: TokenManager> TokenManager for ScopedTokenManager<T> {
    async fn store_access_token(&self, user_id: &str, mut access_token: AccessToken) -> BaffaoResult<()> {
        // Filter scopes to only include allowed ones
        if let Some(scopes) = &access_token.scopes {
            let filtered_scopes = self.filter_scopes(scopes);
            access_token.scopes = Some(filtered_scopes);
        }

        self.inner.store_access_token(user_id, access_token).await
    }

    async fn get_access_token(&self, user_id: &str) -> BaffaoResult<Option<AccessToken>> {
        self.inner.get_access_token(user_id).await
    }

    async fn store_refresh_token(&self, user_id: &str, refresh_token: RefreshToken) -> BaffaoResult<()> {
        self.inner.store_refresh_token(user_id, refresh_token).await
    }

    async fn get_refresh_token(&self, user_id: &str) -> BaffaoResult<Option<RefreshToken>> {
        self.inner.get_refresh_token(user_id).await
    }

    async fn revoke_tokens(&self, user_id: &str) -> BaffaoResult<()> {
        self.inner.revoke_tokens(user_id).await
    }

    async fn get_access_token_for_scope(&self, user_id: &str, required_scopes: &[String]) -> BaffaoResult<Option<AccessToken>> {
        // Validate requested scopes
        self.validate_scopes(required_scopes)?;

        // Call the inner implementation
        self.inner.get_access_token_for_scope(user_id, required_scopes).await
    }
}