//! Storage for CIBA authentication requests.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::Mutex;

use super::error::{CibaError, CibaResult};
use super::models::{AuthenticationRequest, AuthStatus};

/// Trait for storing and retrieving CIBA authentication requests.
#[async_trait]
pub trait CibaRequestStore: Send + Sync {
    /// Store a new authentication request.
    async fn store_request(&self, request: AuthenticationRequest) -> CibaResult<()>;
    
    /// Retrieve an authentication request by ID.
    async fn get_request(&self, request_id: &str) -> CibaResult<Option<AuthenticationRequest>>;
    
    /// Update the status of an authentication request.
    async fn update_request_status(&self, request_id: &str, status: AuthStatus) -> CibaResult<()>;
    
    /// Delete an authentication request.
    async fn delete_request(&self, request_id: &str) -> CibaResult<()>;
    
    /// Get requests by user identifier.
    async fn get_requests_by_user(&self, login_hint: &str) -> CibaResult<Vec<AuthenticationRequest>>;
    
    /// Get requests by client ID.
    async fn get_requests_by_client(&self, client_id: &str) -> CibaResult<Vec<AuthenticationRequest>>;
    
    /// Clean up expired requests.
    async fn cleanup_expired_requests(&self) -> CibaResult<u64>;
}

/// In-memory implementation of CibaRequestStore.
#[derive(Default, Clone)]
pub struct InMemoryCibaRequestStore {
    requests: Arc<Mutex<HashMap<String, AuthenticationRequest>>>,
}

impl InMemoryCibaRequestStore {
    /// Create a new in-memory CIBA request store.
    pub fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl CibaRequestStore for InMemoryCibaRequestStore {
    async fn store_request(&self, request: AuthenticationRequest) -> CibaResult<()> {
        let mut requests = self.requests.lock().await;
        requests.insert(request.id.clone(), request);
        Ok(())
    }
    
    async fn get_request(&self, request_id: &str) -> CibaResult<Option<AuthenticationRequest>> {
        let requests = self.requests.lock().await;
        
        if let Some(request) = requests.get(request_id) {
            if request.is_expired() && request.status == AuthStatus::Pending {
                // Request is expired but status hasn't been updated yet
                // Return a cloned request with updated status
                let mut updated_request = request.clone();
                updated_request.status = AuthStatus::Expired;
                return Ok(Some(updated_request));
            }
            Ok(Some(request.clone()))
        } else {
            Ok(None)
        }
    }
    
    async fn update_request_status(&self, request_id: &str, status: AuthStatus) -> CibaResult<()> {
        let mut requests = self.requests.lock().await;
        
        if let Some(request) = requests.get_mut(request_id) {
            if request.status == AuthStatus::Pending || 
               (status == AuthStatus::Cancelled && request.status != AuthStatus::Expired) {
                request.status = status;
                Ok(())
            } else {
                Err(CibaError::ValidationError("Cannot update status for non-pending request".to_string()))
            }
        } else {
            Err(CibaError::NotFound(format!("Request not found: {}", request_id)))
        }
    }
    
    async fn delete_request(&self, request_id: &str) -> CibaResult<()> {
        let mut requests = self.requests.lock().await;
        requests.remove(request_id);
        Ok(())
    }
    
    async fn get_requests_by_user(&self, login_hint: &str) -> CibaResult<Vec<AuthenticationRequest>> {
        let requests = self.requests.lock().await;
        
        let user_requests: Vec<AuthenticationRequest> = requests
            .values()
            .filter(|r| r.login_hint == login_hint)
            .cloned()
            .collect();
            
        Ok(user_requests)
    }
    
    async fn get_requests_by_client(&self, client_id: &str) -> CibaResult<Vec<AuthenticationRequest>> {
        let requests = self.requests.lock().await;
        
        let client_requests: Vec<AuthenticationRequest> = requests
            .values()
            .filter(|r| r.client_id == client_id)
            .cloned()
            .collect();
            
        Ok(client_requests)
    }
    
    async fn cleanup_expired_requests(&self) -> CibaResult<u64> {
        let mut requests = self.requests.lock().await;
        let now = Utc::now();
        
        let mut expired_count = 0;
        let mut to_remove = Vec::new();
        
        // Find expired requests
        for (id, request) in requests.iter_mut() {
            if request.expires_at <= now && request.status == AuthStatus::Pending {
                request.status = AuthStatus::Expired;
                expired_count += 1;
            }
            
            // Mark for removal if expired more than an hour ago
            // This is for garbage collection
            if request.expires_at <= now - chrono::Duration::hours(1) {
                to_remove.push(id.clone());
            }
        }
        
        // Remove old expired requests
        for id in to_remove {
            requests.remove(&id);
        }
        
        Ok(expired_count)
    }
}