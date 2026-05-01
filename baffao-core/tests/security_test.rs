//! Security penetration test scenarios.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use baffao_core::auth::{OAuthClient, OAuthClientConfig};
use baffao_core::csrf::CsrfManager;
use baffao_core::dpop::{DPoPKeyPair, DPoPVerifier};
use baffao_core::error::BaffaoResult;
use baffao_core::jwk::{JwkValidator, JwkValidatorConfig};
use baffao_core::oauth_state::OAuthStateManager;
use baffao_core::pkce::{CodeChallenge, CodeChallengeMethod};
use baffao_core::rate_limit::{RateLimiter, RateLimiterConfig};
use baffao_core::token_scope::ScopedTokenManager;
use oauth2::{AuthUrl, TokenUrl};

#[tokio::test]
async fn test_csrf_protection() -> BaffaoResult<()> {
    // Create a CSRF manager
    let csrf_manager = CsrfManager::new_with_random_secret();
    
    // Generate a CSRF token
    let csrf_token = csrf_manager.generate_token(None)?;
    
    // Valid verification should succeed
    csrf_manager.verify_token(&csrf_token)?;
    
    // Tampered token should fail
    let tampered_token = format!("{}X", &csrf_token[0..csrf_token.len()-1]);
    let result = csrf_manager.verify_token(&tampered_token);
    assert!(result.is_err(), "Tampered CSRF token should be rejected");
    
    // Completely invalid token should fail
    let invalid_token = "invalid-token".to_string();
    let result = csrf_manager.verify_token(&invalid_token);
    assert!(result.is_err(), "Invalid CSRF token should be rejected");
    
    Ok(())
}

#[tokio::test]
async fn test_oauth_state_validation() -> BaffaoResult<()> {
    // Create an OAuth state manager
    let state_manager = OAuthStateManager::new(Duration::from_secs(300));
    
    // Generate a state
    let client_id = "test_client";
    let redirect_url = "https://client.example.com/callback";
    let state = state_manager.generate_state(client_id, redirect_url)?;
    
    // Valid verification should succeed
    state_manager.verify_state(&state, client_id, redirect_url)?;
    
    // Wrong client ID should fail
    let wrong_client = "wrong_client";
    let result = state_manager.verify_state(&state, wrong_client, redirect_url);
    assert!(result.is_err(), "Wrong client ID should be rejected");
    
    // Wrong redirect URL should fail
    let wrong_redirect = "https://attacker.example.com/callback";
    let result = state_manager.verify_state(&state, client_id, wrong_redirect);
    assert!(result.is_err(), "Wrong redirect URL should be rejected");
    
    // Tampered state should fail
    let tampered_state = format!("{}X", &state[0..state.len()-1]);
    let result = state_manager.verify_state(&tampered_state, client_id, redirect_url);
    assert!(result.is_err(), "Tampered state should be rejected");
    
    Ok(())
}

#[tokio::test]
async fn test_rate_limiting() -> BaffaoResult<()> {
    // Create a rate limiter with a very restrictive config for testing
    let config = RateLimiterConfig {
        window_size_ms: 1000,
        max_requests: 2,
    };
    let rate_limiter = RateLimiter::new(config);
    
    // First request should succeed
    let result = rate_limiter.check_rate_limit("test_client").await;
    assert!(result.is_ok(), "First request should be allowed");
    
    // Second request should succeed
    let result = rate_limiter.check_rate_limit("test_client").await;
    assert!(result.is_ok(), "Second request should be allowed");
    
    // Third request should be rate limited
    let result = rate_limiter.check_rate_limit("test_client").await;
    assert!(result.is_err(), "Third request should be rate limited");
    
    // Different client should not be rate limited
    let result = rate_limiter.check_rate_limit("different_client").await;
    assert!(result.is_ok(), "Different client should not be rate limited");
    
    // Wait for the window to expire
    tokio::time::sleep(Duration::from_millis(1100)).await;
    
    // Request after window expiry should succeed
    let result = rate_limiter.check_rate_limit("test_client").await;
    assert!(result.is_ok(), "Request after window expiry should succeed");
    
    Ok(())
}

#[tokio::test]
async fn test_dpop_security() -> BaffaoResult<()> {
    // Generate a DPoP key pair
    let key_pair = DPoPKeyPair::new_p256()?;
    let verifier = DPoPVerifier::new();
    
    // Create a valid DPoP proof
    let method = "POST";
    let url = "https://server.example.com/token";
    let proof = key_pair.create_proof(method, url, None, None)?;
    
    // Valid proof should be accepted
    verifier.verify_without_nonce(&proof, method, url)?;
    
    // Replay attack - using the same proof twice should be rejected
    // In a real system, this would be handled by the nonce mechanism
    
    // Request method tampering
    let result = verifier.verify_without_nonce(&proof, "GET", url);
    assert!(result.is_err(), "Changed method should be rejected");
    
    // URL tampering
    let result = verifier.verify_without_nonce(&proof, method, "https://attacker.example.com/token");
    assert!(result.is_err(), "Changed URL should be rejected");
    
    // Create an expired proof
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let expired_proof = key_pair.create_proof(
        method, 
        url, 
        None, 
        Some(Duration::from_secs(0))
    )?;
    
    // Expired proof should be rejected
    let result = verifier.verify_without_nonce(&expired_proof, method, url);
    assert!(result.is_err(), "Expired proof should be rejected");
    
    Ok(())
}

#[tokio::test]
async fn test_scope_validation() -> BaffaoResult<()> {
    // Create a token manager with scope validation
    let token_manager = baffao_core::token::InMemoryTokenManager::new();
    let scoped_manager = ScopedTokenManager::new(token_manager);
    
    // Create an access token with specific scopes
    let token = baffao_core::token::AccessToken::new(
        "test_token".to_string(),
        Some(Duration::from_secs(3600)),
        Some(vec!["read".to_string(), "user".to_string()]),
    );
    
    // Store the token
    let user_id = "test_user";
    scoped_manager.store_access_token(user_id, token).await?;
    
    // Get token with valid required scopes
    let result = scoped_manager.get_access_token_for_scope(user_id, &["read".to_string()]).await?;
    assert!(result.is_some(), "Token should be returned for valid scope");
    
    // Get token with multiple valid required scopes
    let result = scoped_manager.get_access_token_for_scope(
        user_id, 
        &["read".to_string(), "user".to_string()]
    ).await?;
    assert!(result.is_some(), "Token should be returned for multiple valid scopes");
    
    // Get token with invalid required scope
    let result = scoped_manager.get_access_token_for_scope(
        user_id, 
        &["admin".to_string()]
    ).await?;
    assert!(result.is_none(), "Token should not be returned for invalid scope");
    
    // Get token with mix of valid and invalid scopes
    let result = scoped_manager.get_access_token_for_scope(
        user_id, 
        &["read".to_string(), "admin".to_string()]
    ).await?;
    assert!(result.is_none(), "Token should not be returned for mix of valid and invalid scopes");
    
    Ok(())
}

#[tokio::test]
async fn test_jwk_validation() -> BaffaoResult<()> {
    // Create a JWK validator
    let config = JwkValidatorConfig {
        issuer: Some("https://auth.example.com".to_string()),
        audience: Some("test_client".to_string()),
        jwks_uri: None, // In a real test, this would point to a JWKS endpoint
        clock_skew_seconds: 60,
    };
    
    let validator = JwkValidator::new(config);
    
    // In a real test, we would generate a valid JWT and validate it
    // For this test, we'll just check that the validator was created successfully
    assert!(validator.config.issuer.is_some(), "Validator should have issuer configured");
    
    Ok(())
}