//! Tests for the CIBA implementation.

use std::time::Duration;

use crate::token::InMemoryTokenManager;
use super::models::{AuthenticationRequest, AuthStatus};
use super::store::{CibaRequestStore, InMemoryCibaRequestStore};
use super::verification::{CibaVerifier, StandardCibaVerifier};
use super::error::CibaResult;

#[tokio::test]
async fn test_authentication_request_lifecycle() -> CibaResult<()> {
    // Set up the store
    let store = InMemoryCibaRequestStore::new();
    
    // Create a request
    let request = AuthenticationRequest::new(
        "user@example.com".to_string(),
        Some("Please confirm login on your device".to_string()),
        Some("openid profile".to_string()),
        "client123".to_string(),
        Some(300), // 5 minutes expiry
        None,
        None,
        None,
    );
    
    let request_id = request.id.clone();
    
    // Store the request
    store.store_request(request).await?;
    
    // Retrieve the request
    let retrieved = store.get_request(&request_id).await?;
    assert!(retrieved.is_some(), "Request should be retrieved");
    
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.status, AuthStatus::Pending, "Initial status should be pending");
    
    // Update status to approved
    store.update_request_status(&request_id, AuthStatus::Approved).await?;
    
    // Check updated status
    let updated = store.get_request(&request_id).await?;
    assert!(updated.is_some(), "Request should still exist");
    assert_eq!(updated.unwrap().status, AuthStatus::Approved, "Status should be approved");
    
    // Delete the request
    store.delete_request(&request_id).await?;
    
    // Verify it's gone
    let deleted = store.get_request(&request_id).await?;
    assert!(deleted.is_none(), "Request should be deleted");
    
    Ok(())
}

#[tokio::test]
async fn test_expiry_handling() -> CibaResult<()> {
    // Set up the store
    let store = InMemoryCibaRequestStore::new();
    
    // Create a request with 1 second expiry
    let mut request = AuthenticationRequest::new(
        "user@example.com".to_string(),
        None,
        None,
        "client123".to_string(),
        Some(1), // 1 second expiry
        None,
        None,
        None,
    );
    
    let request_id = request.id.clone();
    
    // Store the request
    store.store_request(request.clone()).await?;
    
    // Wait for expiration
    tokio::time::sleep(Duration::from_secs(2)).await;
    
    // Get the request - should be marked as expired
    let expired = store.get_request(&request_id).await?;
    assert!(expired.is_some(), "Request should still exist");
    
    let expired = expired.unwrap();
    assert_eq!(expired.status, AuthStatus::Expired, "Status should be automatically updated to expired");
    
    // Clean up expired requests
    let cleaned = store.cleanup_expired_requests().await?;
    assert_eq!(cleaned, 1, "One request should be marked as expired");
    
    Ok(())
}

#[tokio::test]
async fn test_ciba_verification() -> CibaResult<()> {
    // Set up the store and token manager
    let store = InMemoryCibaRequestStore::new();
    let token_manager = InMemoryTokenManager::new();
    
    // Create the verifier
    let verifier = StandardCibaVerifier::new(
        store.clone(),
        token_manager.clone(),
        None, // Use default binding message verifier
        None, // Use default user code verifier
    );
    
    // Create a request
    let request = AuthenticationRequest::new(
        "user123".to_string(),
        Some("Confirm login on your phone".to_string()),
        Some("openid profile".to_string()),
        "client456".to_string(),
        Some(300),
        None,
        Some("123456".to_string()), // User code
        None,
    );
    
    let request_id = request.id.clone();
    
    // Store the request
    store.store_request(request).await?;
    
    // Verify binding message
    let retrieved = store.get_request(&request_id).await?;
    assert!(retrieved.is_some(), "Request should be retrieved");
    
    let retrieved = retrieved.unwrap();
    assert!(verifier.verify_binding_message(&retrieved, "Confirm login on your phone"), 
            "Binding message should be verified");
    
    assert!(!verifier.verify_binding_message(&retrieved, "Wrong message"), 
            "Wrong binding message should fail verification");
    
    // Verify user code
    assert!(verifier.verify_user_code(&retrieved, "123456"), 
            "User code should be verified");
    
    assert!(!verifier.verify_user_code(&retrieved, "999999"), 
            "Wrong user code should fail verification");
    
    // Approve the request
    verifier.verify_request(&request_id, "user123").await?;
    
    // Check updated status
    assert_eq!(verifier.check_request_status(&request_id).await?, AuthStatus::Approved, 
               "Status should be approved");
    
    // Issue tokens
    let (access_token, refresh_token) = verifier.issue_tokens(&request_id, "user123").await?;
    
    // Verify tokens were created correctly
    assert_eq!(access_token.scopes.unwrap().join(" "), "openid profile", 
               "Access token should have correct scopes");
               
    assert!(refresh_token.is_some(), "Refresh token should be created");
    
    // Verify the request was deleted after token issuance
    let deleted = store.get_request(&request_id).await?;
    assert!(deleted.is_none(), "Request should be deleted after token issuance");
    
    Ok(())
}

#[tokio::test]
async fn test_request_denial() -> CibaResult<()> {
    // Set up the store and token manager
    let store = InMemoryCibaRequestStore::new();
    let token_manager = InMemoryTokenManager::new();
    
    // Create the verifier
    let verifier = StandardCibaVerifier::new(
        store.clone(),
        token_manager,
        None,
        None,
    );
    
    // Create a request
    let request = AuthenticationRequest::new(
        "user456".to_string(),
        None,
        Some("openid".to_string()),
        "client789".to_string(),
        Some(300),
        None,
        None,
        None,
    );
    
    let request_id = request.id.clone();
    
    // Store the request
    store.store_request(request).await?;
    
    // Deny the request
    verifier.deny_request(&request_id, "user456").await?;
    
    // Check updated status
    assert_eq!(verifier.check_request_status(&request_id).await?, AuthStatus::Denied, 
               "Status should be denied");
               
    // Attempting to approve a denied request should fail
    let result = verifier.verify_request(&request_id, "user456").await;
    assert!(result.is_err(), "Approving a denied request should fail");
    
    Ok(())
}