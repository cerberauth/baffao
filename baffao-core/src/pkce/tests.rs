//! Tests for PKCE implementation.

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

use super::{CodeChallenge, CodeChallengeMethod, PkceStore};
use crate::error::BaffaoResult;

#[tokio::test]
async fn test_code_challenge_creation() -> BaffaoResult<()> {
    // Create a new code challenge with S256 method
    let challenge = CodeChallenge::new_s256();
    
    // Verify properties
    assert_eq!(challenge.method, CodeChallengeMethod::S256);
    assert!(!challenge.verifier.is_empty(), "Verifier should not be empty");
    assert!(!challenge.challenge.is_empty(), "Challenge should not be empty");
    assert_ne!(challenge.verifier, challenge.challenge, "S256 challenge should differ from verifier");
    
    // Create a new code challenge with Plain method
    let challenge = CodeChallenge::new(CodeChallengeMethod::Plain);
    
    // Verify properties for plain method
    assert_eq!(challenge.method, CodeChallengeMethod::Plain);
    assert!(!challenge.verifier.is_empty(), "Verifier should not be empty");
    assert!(!challenge.challenge.is_empty(), "Challenge should not be empty");
    assert_eq!(challenge.verifier, challenge.challenge, "Plain challenge should equal verifier");
    
    Ok(())
}

#[tokio::test]
async fn test_code_challenge_verification() -> BaffaoResult<()> {
    // Create a new code challenge with S256 method
    let challenge = CodeChallenge::new_s256();
    let verifier = challenge.verifier.clone();
    
    // Verify with correct verifier
    challenge.verify(&verifier, None)?;
    
    // Verify with incorrect verifier should fail
    let result = challenge.verify("incorrect-verifier", None);
    assert!(result.is_err(), "Verification with incorrect verifier should fail");
    
    // Create a challenge with Plain method
    let plain_challenge = CodeChallenge::new(CodeChallengeMethod::Plain);
    let plain_verifier = plain_challenge.verifier.clone();
    
    // Verify with correct verifier
    plain_challenge.verify(&plain_verifier, None)?;
    
    // Verify with incorrect verifier should fail
    let result = plain_challenge.verify("incorrect-verifier", None);
    assert!(result.is_err(), "Verification with incorrect verifier should fail");
    
    Ok(())
}

#[tokio::test]
async fn test_code_challenge_expiration() -> BaffaoResult<()> {
    // Create a new code challenge
    let mut challenge = CodeChallenge::new_s256();
    let verifier = challenge.verifier.clone();
    
    // Set created_at to 1 hour ago
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    challenge.created_at = now - 3600;
    
    // Verify with a max age of 30 minutes should fail
    let result = challenge.verify(&verifier, Some(Duration::from_secs(1800)));
    assert!(result.is_err(), "Verification with expired challenge should fail");
    
    // Verify with a max age of 2 hours should succeed
    let result = challenge.verify(&verifier, Some(Duration::from_secs(7200)));
    assert!(result.is_ok(), "Verification with non-expired challenge should succeed");
    
    Ok(())
}

#[tokio::test]
async fn test_pkce_store() -> BaffaoResult<()> {
    // Create a new PKCE store
    let store = PkceStore::new();
    
    // Create a new challenge
    let challenge = CodeChallenge::new_s256();
    let verifier = challenge.verifier.clone();
    
    // Store the challenge
    let state = "test-state";
    store.store_challenge(state, challenge).await?;
    
    // Get the challenge
    let retrieved = store.get_challenge(state).await?;
    assert!(retrieved.is_some(), "Should retrieve stored challenge");
    
    // Verify verifier
    store.verify_verifier(state, &verifier, None).await?;
    
    // Challenge should be removed after verification
    let retrieved = store.get_challenge(state).await?;
    assert!(retrieved.is_none(), "Challenge should be removed after verification");
    
    // Verify with non-existent state should fail
    let result = store.verify_verifier("non-existent", &verifier, None).await;
    assert!(result.is_err(), "Verification with non-existent state should fail");
    
    Ok(())
}

#[tokio::test]
async fn test_pkce_store_cleanup() -> BaffaoResult<()> {
    // Create a new PKCE store
    let store = PkceStore::new();
    
    // Create challenges with different ages
    let mut new_challenge = CodeChallenge::new_s256();
    let mut old_challenge = CodeChallenge::new_s256();
    
    // Set created_at times
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    new_challenge.created_at = now;
    old_challenge.created_at = now - 3600; // 1 hour old
    
    // Store the challenges
    store.store_challenge("new-state", new_challenge).await?;
    store.store_challenge("old-state", old_challenge).await?;
    
    // Cleanup with 30 minutes max age
    store.cleanup(Duration::from_secs(1800)).await?;
    
    // Check that only the new challenge remains
    let new_retrieved = store.get_challenge("new-state").await?;
    let old_retrieved = store.get_challenge("old-state").await?;
    
    assert!(new_retrieved.is_some(), "New challenge should remain after cleanup");
    assert!(old_retrieved.is_none(), "Old challenge should be removed after cleanup");
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_verifications() -> BaffaoResult<()> {
    // Create a new PKCE store
    let store = PkceStore::new();
    
    // Create multiple challenges
    let challenge1 = CodeChallenge::new_s256();
    let challenge2 = CodeChallenge::new_s256();
    let verifier1 = challenge1.verifier.clone();
    let verifier2 = challenge2.verifier.clone();
    
    // Store the challenges
    store.store_challenge("state1", challenge1).await?;
    store.store_challenge("state2", challenge2).await?;
    
    // Spawn two tasks to verify concurrently
    let store_clone = store.clone();
    let handle1 = tokio::spawn(async move {
        let result = store_clone.verify_verifier("state1", &verifier1, None).await;
        (result, store_clone.get_challenge("state1").await)
    });
    
    let store_clone = store.clone();
    let handle2 = tokio::spawn(async move {
        // Small delay to ensure concurrent execution
        sleep(Duration::from_millis(10)).await;
        let result = store_clone.verify_verifier("state2", &verifier2, None).await;
        (result, store_clone.get_challenge("state2").await)
    });
    
    // Wait for both tasks to complete
    let (result1, get1) = handle1.await.unwrap();
    let (result2, get2) = handle2.await.unwrap();
    
    // Both verifications should succeed
    assert!(result1.is_ok(), "First verification should succeed");
    assert!(result2.is_ok(), "Second verification should succeed");
    
    // Both challenges should be removed
    assert!(get1.unwrap().is_none(), "First challenge should be removed");
    assert!(get2.unwrap().is_none(), "Second challenge should be removed");
    
    Ok(())
}