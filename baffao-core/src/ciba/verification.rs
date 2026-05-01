//! CIBA request verification functionality.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::error::{CibaError, CibaResult};
use super::models::{AuthenticationRequest, AuthStatus};
use super::store::CibaRequestStore;
use crate::token::{AccessToken, TokenManager};

/// Interface for CIBA verification operations.
#[async_trait]
pub trait CibaVerifier: Send + Sync {
    /// Verify an authentication request.
    async fn verify_request(&self, request_id: &str, user_id: &str) -> CibaResult<()>;
    
    /// Deny an authentication request.
    async fn deny_request(&self, request_id: &str, user_id: &str) -> CibaResult<()>;
    
    /// Check the status of an authentication request.
    async fn check_request_status(&self, request_id: &str) -> CibaResult<AuthStatus>;
    
    /// Issue tokens for an approved authentication request.
    async fn issue_tokens(
        &self, 
        request_id: &str,
        user_id: &str,
    ) -> CibaResult<(AccessToken, Option<String>)>;
    
    /// Verify the binding message for a request.
    fn verify_binding_message(&self, request: &AuthenticationRequest, binding_message: &str) -> bool;
    
    /// Verify user code for a request.
    fn verify_user_code(&self, request: &AuthenticationRequest, user_code: &str) -> bool;
}

/// Standard implementation of the CibaVerifier trait.
pub struct StandardCibaVerifier<S, T>
where
    S: CibaRequestStore,
    T: TokenManager,
{
    store: S,
    token_manager: T,
    binding_message_verifier: Box<dyn Fn(&AuthenticationRequest, &str) -> bool + Send + Sync>,
    user_code_verifier: Box<dyn Fn(&AuthenticationRequest, &str) -> bool + Send + Sync>,
}

impl<S, T> StandardCibaVerifier<S, T>
where
    S: CibaRequestStore,
    T: TokenManager,
{
    /// Create a new CIBA verifier.
    pub fn new(
        store: S,
        token_manager: T,
        binding_message_verifier: Option<Box<dyn Fn(&AuthenticationRequest, &str) -> bool + Send + Sync>>,
        user_code_verifier: Option<Box<dyn Fn(&AuthenticationRequest, &str) -> bool + Send + Sync>>,
    ) -> Self {
        let default_binding_verifier = Box::new(|request: &AuthenticationRequest, binding_message: &str| {
            request.binding_message.as_ref().map_or(false, |bm| bm == binding_message)
        });
        
        let default_user_code_verifier = Box::new(|request: &AuthenticationRequest, user_code: &str| {
            request.user_code.as_ref().map_or(false, |uc| uc == user_code)
        });
        
        Self {
            store,
            token_manager,
            binding_message_verifier: binding_message_verifier.unwrap_or(default_binding_verifier),
            user_code_verifier: user_code_verifier.unwrap_or(default_user_code_verifier),
        }
    }
    
    /// Get the store.
    pub fn store(&self) -> &S {
        &self.store
    }
    
    /// Get the token manager.
    pub fn token_manager(&self) -> &T {
        &self.token_manager
    }
}

#[async_trait]
impl<S, T> CibaVerifier for StandardCibaVerifier<S, T>
where
    S: CibaRequestStore,
    T: TokenManager,
{
    async fn verify_request(&self, request_id: &str, user_id: &str) -> CibaResult<()> {
        let request = self.store.get_request(request_id).await?
            .ok_or_else(|| CibaError::NotFound(format!("Request not found: {}", request_id)))?;
            
        // Check if request is pending
        if request.status != AuthStatus::Pending {
            return Err(CibaError::ValidationError(format!(
                "Request is not pending, current status: {:?}", request.status
            )));
        }
        
        // Check if request is expired
        if request.is_expired() {
            // Update status to expired
            self.store.update_request_status(request_id, AuthStatus::Expired).await?;
            return Err(CibaError::ExpiredRequest("Authentication request has expired".to_string()));
        }
        
        // Check user identifier
        if request.login_hint != user_id {
            return Err(CibaError::ValidationError(
                "User ID does not match login hint in the request".to_string()
            ));
        }
        
        // Update request status to approved
        self.store.update_request_status(request_id, AuthStatus::Approved).await?;
        
        Ok(())
    }
    
    async fn deny_request(&self, request_id: &str, user_id: &str) -> CibaResult<()> {
        let request = self.store.get_request(request_id).await?
            .ok_or_else(|| CibaError::NotFound(format!("Request not found: {}", request_id)))?;
            
        // Check if request is pending
        if request.status != AuthStatus::Pending {
            return Err(CibaError::ValidationError(format!(
                "Request is not pending, current status: {:?}", request.status
            )));
        }
        
        // Check if request is expired
        if request.is_expired() {
            // Update status to expired
            self.store.update_request_status(request_id, AuthStatus::Expired).await?;
            return Err(CibaError::ExpiredRequest("Authentication request has expired".to_string()));
        }
        
        // Check user identifier
        if request.login_hint != user_id {
            return Err(CibaError::ValidationError(
                "User ID does not match login hint in the request".to_string()
            ));
        }
        
        // Update request status to denied
        self.store.update_request_status(request_id, AuthStatus::Denied).await?;
        
        Ok(())
    }
    
    async fn check_request_status(&self, request_id: &str) -> CibaResult<AuthStatus> {
        let request = self.store.get_request(request_id).await?
            .ok_or_else(|| CibaError::NotFound(format!("Request not found: {}", request_id)))?;
            
        // If the request is pending but expired, update its status
        if request.status == AuthStatus::Pending && request.is_expired() {
            self.store.update_request_status(request_id, AuthStatus::Expired).await?;
            Ok(AuthStatus::Expired)
        } else {
            Ok(request.status)
        }
    }
    
    async fn issue_tokens(
        &self, 
        request_id: &str,
        user_id: &str,
    ) -> CibaResult<(AccessToken, Option<String>)> {
        let request = self.store.get_request(request_id).await?
            .ok_or_else(|| CibaError::NotFound(format!("Request not found: {}", request_id)))?;
            
        // Check if request is approved
        if request.status != AuthStatus::Approved {
            return Err(CibaError::ValidationError(format!(
                "Request is not approved, current status: {:?}", request.status
            )));
        }
        
        // Check user identifier
        if request.login_hint != user_id {
            return Err(CibaError::ValidationError(
                "User ID does not match login hint in the request".to_string()
            ));
        }
        
        // Parse scopes
        let scopes = request.scope.as_ref().map(|s| {
            s.split_whitespace()
                .map(String::from)
                .collect::<Vec<String>>()
        });
        
        // Determine token expiry
        let expires_in = if let Some(requested_expiry) = request.requested_expiry {
            if requested_expiry > 0 {
                Some(Duration::from_secs(requested_expiry as u64))
            } else {
                None // Use default
            }
        } else {
            None // Use default
        };
        
        // Generate an access token
        let access_token = AccessToken::new(
            uuid::Uuid::new_v4().to_string(),
            expires_in,
            scopes,
        );
        
        // Store the token
        self.token_manager.store_access_token(user_id, access_token.clone()).await
            .map_err(|e| CibaError::ServerError(format!("Failed to store token: {}", e)))?;
            
        // Generate a refresh token (optional)
        let refresh_token = Some(uuid::Uuid::new_v4().to_string());
        
        if let Some(refresh_token_str) = &refresh_token {
            // Store the refresh token
            let refresh_token_obj = crate::token::RefreshToken::new(refresh_token_str.clone());
            self.token_manager.store_refresh_token(user_id, refresh_token_obj).await
                .map_err(|e| CibaError::ServerError(format!("Failed to store refresh token: {}", e)))?;
        }
        
        // Delete the authentication request - it's no longer needed
        self.store.delete_request(request_id).await?;
        
        Ok((access_token, refresh_token))
    }
    
    fn verify_binding_message(&self, request: &AuthenticationRequest, binding_message: &str) -> bool {
        (self.binding_message_verifier)(request, binding_message)
    }
    
    fn verify_user_code(&self, request: &AuthenticationRequest, user_code: &str) -> bool {
        (self.user_code_verifier)(request, user_code)
    }
}