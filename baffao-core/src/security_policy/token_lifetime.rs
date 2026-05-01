//! Token lifetime policies.
//!
//! This module provides configurable token lifetime policies that can be used
//! to enforce different token expiration rules based on context.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{BaffaoError, BaffaoResult};
use crate::token::{AccessToken, RefreshToken, TokenManager};

/// Token type enum for policy application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenType {
    /// Access token
    AccessToken,
    /// Refresh token
    RefreshToken,
    /// ID token
    IdToken,
    /// Authorization code
    AuthorizationCode,
}

impl ToString for TokenType {
    fn to_string(&self) -> String {
        match self {
            TokenType::AccessToken => "access_token",
            TokenType::RefreshToken => "refresh_token",
            TokenType::IdToken => "id_token",
            TokenType::AuthorizationCode => "authorization_code",
        }.to_string()
    }
}

/// Context for token lifetime policy decisions.
#[derive(Debug, Clone)]
pub struct TokenLifetimeContext {
    /// The client ID requesting the token
    pub client_id: String,
    /// The user ID the token is for
    pub user_id: String,
    /// Requested scopes
    pub scopes: Option<Vec<String>>,
    /// IP address of the client
    pub ip_address: Option<String>,
    /// User agent of the client
    pub user_agent: Option<String>,
    /// Authentication method used
    pub auth_method: Option<String>,
    /// Authentication time
    pub auth_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Additional context data
    pub additional_data: HashMap<String, String>,
}

/// Token lifetime policy interface.
#[async_trait]
pub trait TokenLifetimePolicy: Send + Sync {
    /// Determine the lifetime for a token based on context.
    async fn get_token_lifetime(
        &self,
        token_type: TokenType,
        context: &TokenLifetimeContext,
    ) -> BaffaoResult<Option<Duration>>;
    
    /// Validate if a token should be still considered valid.
    async fn validate_token(
        &self,
        token_type: TokenType,
        token_age: Duration,
        context: &TokenLifetimeContext,
    ) -> BaffaoResult<bool>;
}

/// Token lifetime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenLifetimeConfig {
    /// Default lifetime for access tokens (in seconds)
    #[serde(default = "default_access_token_lifetime")]
    pub default_access_token_lifetime: u64,
    
    /// Default lifetime for refresh tokens (in seconds)
    #[serde(default = "default_refresh_token_lifetime")]
    pub default_refresh_token_lifetime: u64,
    
    /// Default lifetime for ID tokens (in seconds)
    #[serde(default = "default_id_token_lifetime")]
    pub default_id_token_lifetime: u64,
    
    /// Default lifetime for authorization codes (in seconds)
    #[serde(default = "default_authorization_code_lifetime")]
    pub default_authorization_code_lifetime: u64,
    
    /// Maximum lifetime for access tokens (in seconds)
    #[serde(default = "max_access_token_lifetime")]
    pub max_access_token_lifetime: u64,
    
    /// Maximum lifetime for refresh tokens (in seconds)
    #[serde(default = "max_refresh_token_lifetime")]
    pub max_refresh_token_lifetime: u64,
    
    /// Client-specific token lifetimes
    #[serde(default)]
    pub client_lifetimes: HashMap<String, ClientTokenLifetimeConfig>,
    
    /// Scope-specific token lifetimes
    #[serde(default)]
    pub scope_lifetimes: HashMap<String, u64>,
    
    /// Whether to use absolute expiration (true) or sliding expiration (false)
    #[serde(default = "default_absolute_expiration")]
    pub absolute_expiration: bool,
    
    /// Whether to allow refresh token rotation
    #[serde(default = "default_rotate_refresh_tokens")]
    pub rotate_refresh_tokens: bool,
    
    /// Whether tokens issued through refresh tokens should have reduced lifetimes
    #[serde(default = "default_reduce_refreshed_token_lifetime")]
    pub reduce_refreshed_token_lifetime: bool,
    
    /// Factor to reduce refreshed token lifetimes by (if enabled)
    #[serde(default = "default_refreshed_token_lifetime_reduction_factor")]
    pub refreshed_token_lifetime_reduction_factor: f64,
}

fn default_access_token_lifetime() -> u64 { 3600 } // 1 hour
fn default_refresh_token_lifetime() -> u64 { 2592000 } // 30 days
fn default_id_token_lifetime() -> u64 { 3600 } // 1 hour
fn default_authorization_code_lifetime() -> u64 { 300 } // 5 minutes
fn max_access_token_lifetime() -> u64 { 86400 } // 24 hours
fn max_refresh_token_lifetime() -> u64 { 7776000 } // 90 days
fn default_absolute_expiration() -> bool { true }
fn default_rotate_refresh_tokens() -> bool { true }
fn default_reduce_refreshed_token_lifetime() -> bool { false }
fn default_refreshed_token_lifetime_reduction_factor() -> f64 { 0.9 } // 90%

impl Default for TokenLifetimeConfig {
    fn default() -> Self {
        Self {
            default_access_token_lifetime: default_access_token_lifetime(),
            default_refresh_token_lifetime: default_refresh_token_lifetime(),
            default_id_token_lifetime: default_id_token_lifetime(),
            default_authorization_code_lifetime: default_authorization_code_lifetime(),
            max_access_token_lifetime: max_access_token_lifetime(),
            max_refresh_token_lifetime: max_refresh_token_lifetime(),
            client_lifetimes: HashMap::new(),
            scope_lifetimes: HashMap::new(),
            absolute_expiration: default_absolute_expiration(),
            rotate_refresh_tokens: default_rotate_refresh_tokens(),
            reduce_refreshed_token_lifetime: default_reduce_refreshed_token_lifetime(),
            refreshed_token_lifetime_reduction_factor: default_refreshed_token_lifetime_reduction_factor(),
        }
    }
}

/// Client-specific token lifetime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientTokenLifetimeConfig {
    /// Access token lifetime for this client (in seconds)
    pub access_token_lifetime: Option<u64>,
    
    /// Refresh token lifetime for this client (in seconds)
    pub refresh_token_lifetime: Option<u64>,
    
    /// ID token lifetime for this client (in seconds)
    pub id_token_lifetime: Option<u64>,
    
    /// Authorization code lifetime for this client (in seconds)
    pub authorization_code_lifetime: Option<u64>,
    
    /// Whether to use absolute expiration for this client
    pub absolute_expiration: Option<bool>,
    
    /// Whether to allow refresh token rotation for this client
    pub rotate_refresh_tokens: Option<bool>,
    
    /// Whether tokens issued through refresh tokens should have reduced lifetimes
    pub reduce_refreshed_token_lifetime: Option<bool>,
}

/// Standard implementation of TokenLifetimePolicy.
#[derive(Clone)]
pub struct StandardTokenLifetimePolicy {
    /// Token lifetime configuration
    config: TokenLifetimeConfig,
}

impl StandardTokenLifetimePolicy {
    /// Creates a new token lifetime policy with the given configuration.
    pub fn new(config: TokenLifetimeConfig) -> Self {
        Self { config }
    }
    
    /// Gets the configuration.
    pub fn config(&self) -> &TokenLifetimeConfig {
        &self.config
    }
}

#[async_trait]
impl TokenLifetimePolicy for StandardTokenLifetimePolicy {
    async fn get_token_lifetime(
        &self,
        token_type: TokenType,
        context: &TokenLifetimeContext,
    ) -> BaffaoResult<Option<Duration>> {
        // Start with default lifetime based on token type
        let default_lifetime = match token_type {
            TokenType::AccessToken => self.config.default_access_token_lifetime,
            TokenType::RefreshToken => self.config.default_refresh_token_lifetime,
            TokenType::IdToken => self.config.default_id_token_lifetime,
            TokenType::AuthorizationCode => self.config.default_authorization_code_lifetime,
        };
        
        // Check for client-specific configuration
        let client_specific_lifetime = self.config.client_lifetimes
            .get(&context.client_id)
            .and_then(|client_config| match token_type {
                TokenType::AccessToken => client_config.access_token_lifetime,
                TokenType::RefreshToken => client_config.refresh_token_lifetime,
                TokenType::IdToken => client_config.id_token_lifetime,
                TokenType::AuthorizationCode => client_config.authorization_code_lifetime,
            });
        
        // Use client-specific lifetime if available, otherwise use default
        let mut lifetime = client_specific_lifetime.unwrap_or(default_lifetime);
        
        // If token is being refreshed and we're configured to reduce refreshed token lifetime
        let reduce_lifetime = match self.config.client_lifetimes.get(&context.client_id) {
            Some(client_config) => client_config.reduce_refreshed_token_lifetime
                .unwrap_or(self.config.reduce_refreshed_token_lifetime),
            None => self.config.reduce_refreshed_token_lifetime,
        };
        
        // If this is a refreshed token, potentially reduce its lifetime
        if reduce_lifetime && token_type == TokenType::AccessToken && 
           context.additional_data.get("is_refreshed").map_or(false, |v| v == "true") {
            
            let reduction_factor = self.config.refreshed_token_lifetime_reduction_factor;
            lifetime = (lifetime as f64 * reduction_factor).floor() as u64;
        }
        
        // Check for scope-specific configurations
        if let Some(scopes) = &context.scopes {
            // Find the minimum lifetime from all relevant scopes
            for scope in scopes {
                if let Some(scope_lifetime) = self.config.scope_lifetimes.get(scope) {
                    // Use the more restrictive lifetime
                    lifetime = lifetime.min(*scope_lifetime);
                }
            }
        }
        
        // Apply maximum limits
        let max_lifetime = match token_type {
            TokenType::AccessToken => self.config.max_access_token_lifetime,
            TokenType::RefreshToken => self.config.max_refresh_token_lifetime,
            // No maximums for these types
            TokenType::IdToken => u64::MAX,
            TokenType::AuthorizationCode => u64::MAX,
        };
        
        lifetime = lifetime.min(max_lifetime);
        
        // Convert to Duration
        Ok(Some(Duration::from_secs(lifetime)))
    }
    
    async fn validate_token(
        &self,
        token_type: TokenType,
        token_age: Duration,
        context: &TokenLifetimeContext,
    ) -> BaffaoResult<bool> {
        // Get the lifetime policy for this token
        let lifetime = match self.get_token_lifetime(token_type, context).await? {
            Some(lifetime) => lifetime,
            None => return Ok(false), // If no lifetime is specified, token is invalid
        };
        
        // Check if absolute or sliding expiration
        let use_absolute_expiration = match self.config.client_lifetimes.get(&context.client_id) {
            Some(client_config) => client_config.absolute_expiration
                .unwrap_or(self.config.absolute_expiration),
            None => self.config.absolute_expiration,
        };
        
        if use_absolute_expiration {
            // Absolute expiration: token is valid if its age is less than its lifetime
            Ok(token_age < lifetime)
        } else {
            // Sliding expiration: always valid (expiration is extended when used)
            // This is handled by the token manager extending the token
            Ok(true)
        }
    }
}

/// Token lifetime manager that wraps a TokenManager with lifetime policies.
pub struct TokenLifetimeManager<T: TokenManager> {
    /// Inner token manager
    token_manager: T,
    /// Token lifetime policy
    policy: Arc<dyn TokenLifetimePolicy>,
}

impl<T: TokenManager> TokenLifetimeManager<T> {
    /// Creates a new token lifetime manager.
    pub fn new(token_manager: T, policy: Arc<dyn TokenLifetimePolicy>) -> Self {
        Self {
            token_manager,
            policy,
        }
    }
    
    /// Gets the inner token manager.
    pub fn inner(&self) -> &T {
        &self.token_manager
    }
    
    /// Gets the token lifetime policy.
    pub fn policy(&self) -> Arc<dyn TokenLifetimePolicy> {
        self.policy.clone()
    }
}

#[async_trait]
impl<T: TokenManager> TokenManager for TokenLifetimeManager<T> {
    async fn store_access_token(&self, user_id: &str, mut access_token: AccessToken) -> BaffaoResult<()> {
        // Use the token manager directly
        self.token_manager.store_access_token(user_id, access_token).await
    }
    
    async fn get_access_token(&self, user_id: &str) -> BaffaoResult<Option<AccessToken>> {
        // Get the token from the inner manager
        let token = self.token_manager.get_access_token(user_id).await?;
        
        // If no token, return None
        let Some(token) = token else {
            return Ok(None);
        };
        
        // If the token is expired, return None
        if token.is_expired() {
            return Ok(None);
        }
        
        // Create a context for validation
        let context = TokenLifetimeContext {
            client_id: "unknown".to_string(), // Ideally this would be stored with the token
            user_id: user_id.to_string(),
            scopes: token.scopes.clone(),
            ip_address: None,
            user_agent: None,
            auth_method: None,
            auth_time: None,
            additional_data: HashMap::new(),
        };
        
        // Calculate token age
        let now = chrono::Utc::now();
        let token_age = now.signed_duration_since(token.issued_at)
            .to_std()
            .unwrap_or_else(|_| Duration::from_secs(0));
        
        // Validate the token according to policy
        let is_valid = self.policy.validate_token(
            TokenType::AccessToken,
            token_age,
            &context
        ).await?;
        
        if is_valid {
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }
    
    async fn store_refresh_token(&self, user_id: &str, refresh_token: RefreshToken) -> BaffaoResult<()> {
        // Use the token manager directly
        self.token_manager.store_refresh_token(user_id, refresh_token).await
    }
    
    async fn get_refresh_token(&self, user_id: &str) -> BaffaoResult<Option<RefreshToken>> {
        // Use the token manager directly
        self.token_manager.get_refresh_token(user_id).await
    }
    
    async fn revoke_tokens(&self, user_id: &str) -> BaffaoResult<()> {
        // Use the token manager directly
        self.token_manager.revoke_tokens(user_id).await
    }
    
    async fn get_access_token_for_scope(&self, user_id: &str, required_scopes: &[String]) -> BaffaoResult<Option<AccessToken>> {
        // Get the token from the inner manager
        let token = self.token_manager.get_access_token_for_scope(user_id, required_scopes).await?;
        
        // If no token, return None
        let Some(token) = token else {
            return Ok(None);
        };
        
        // Create a context for validation
        let context = TokenLifetimeContext {
            client_id: "unknown".to_string(), // Ideally this would be stored with the token
            user_id: user_id.to_string(),
            scopes: token.scopes.clone(),
            ip_address: None,
            user_agent: None,
            auth_method: None,
            auth_time: None,
            additional_data: HashMap::new(),
        };
        
        // Calculate token age
        let now = chrono::Utc::now();
        let token_age = now.signed_duration_since(token.issued_at)
            .to_std()
            .unwrap_or_else(|_| Duration::from_secs(0));
        
        // Validate the token according to policy
        let is_valid = self.policy.validate_token(
            TokenType::AccessToken,
            token_age,
            &context
        ).await?;
        
        if is_valid {
            Ok(Some(token))
        } else {
            Ok(None)
        }
    }
}