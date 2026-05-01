//! Tests for DPoP token binding implementation.

use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{DPoPVerifier, DPoPKeyPair};
use crate::error::BaffaoResult;

/// Create a test DPoP token.
fn create_dpop_token(
    key_pair: &DPoPKeyPair,
    htm: &str,
    htu: &str,
    jti: &str,
    valid: bool,
    expired: bool,
) -> BaffaoResult<String> {
    // Define DPoP JWT payload
    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        jti: String,
        htm: String,
        htu: String,
        iat: i64,
        exp: i64,
    }

    // Calculate current time and expiry
    let now = SystemTime::now();
    let unix_time = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
        
    let expires_in = if expired {
        unix_time - 60 // Expired 1 minute ago
    } else {
        unix_time + 300 // Valid for 5 minutes
    };
    
    // Create claims
    let claims = Claims {
        jti: jti.to_string(),
        htm: if valid { htm.to_string() } else { "INVALID".to_string() },
        htu: if valid { htu.to_string() } else { "INVALID".to_string() },
        iat: unix_time,
        exp: expires_in,
    };
    
    // Create JWT header
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(serde_json::from_str(&key_pair.public_jwk()?)?);
    
    // Encode the token
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(&key_pair.private_key_pem.as_bytes())?,
    )?;
    
    Ok(token)
}

#[tokio::test]
async fn test_dpop_verification() -> BaffaoResult<()> {
    // Generate a key pair for DPoP
    let key_pair = DPoPKeyPair::generate()?;
    
    // Create a DPoP verifier
    let verifier = DPoPVerifier::new();
    
    // Request parameters
    let htm = "POST";
    let htu = "https://server.example.com/token";
    let jti = "abc123";
    
    // Create a valid DPoP token
    let valid_token = create_dpop_token(&key_pair, htm, htu, jti, true, false)?;
    
    // Verify the valid token
    let result = verifier.verify(&valid_token, htm, htu).await?;
    assert!(result.is_some(), "Valid token should be verified");
    
    // Create an invalid method token
    let invalid_method_token = create_dpop_token(&key_pair, "GET", htu, jti, true, false)?;
    
    // Verify should fail due to method mismatch
    let result = verifier.verify(&invalid_method_token, htm, htu).await;
    assert!(result.is_err(), "Token with incorrect method should fail verification");
    
    // Create an invalid URL token
    let invalid_url_token = create_dpop_token(&key_pair, htm, "https://wrong.example.com", jti, true, false)?;
    
    // Verify should fail due to URL mismatch
    let result = verifier.verify(&invalid_url_token, htm, htu).await;
    assert!(result.is_err(), "Token with incorrect URL should fail verification");
    
    // Create an expired token
    let expired_token = create_dpop_token(&key_pair, htm, htu, jti, true, true)?;
    
    // Verify should fail due to expiration
    let result = verifier.verify(&expired_token, htm, htu).await;
    assert!(result.is_err(), "Expired token should fail verification");
    
    Ok(())
}

#[tokio::test]
async fn test_dpop_replay_protection() -> BaffaoResult<()> {
    // Generate a key pair for DPoP
    let key_pair = DPoPKeyPair::generate()?;
    
    // Create a DPoP verifier with a small cache (to test cache eviction)
    let verifier = DPoPVerifier::with_cache_size(2);
    
    // Request parameters
    let htm = "POST";
    let htu = "https://server.example.com/token";
    
    // Create three DPoP tokens with different JTIs
    let token1 = create_dpop_token(&key_pair, htm, htu, "jti1", true, false)?;
    let token2 = create_dpop_token(&key_pair, htm, htu, "jti2", true, false)?;
    let token3 = create_dpop_token(&key_pair, htm, htu, "jti3", true, false)?;
    
    // Verify token1
    let result = verifier.verify(&token1, htm, htu).await?;
    assert!(result.is_some(), "First use of token1 should succeed");
    
    // Verify token1 again (should fail as replay)
    let result = verifier.verify(&token1, htm, htu).await;
    assert!(result.is_err(), "Second use of token1 should fail (replay protection)");
    
    // Verify token2
    let result = verifier.verify(&token2, htm, htu).await?;
    assert!(result.is_some(), "First use of token2 should succeed");
    
    // Verify token3 (should evict token1 from cache due to LRU)
    let result = verifier.verify(&token3, htm, htu).await?;
    assert!(result.is_some(), "First use of token3 should succeed");
    
    // Wait for cache to expire
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    // Token1 should work again as it should have been evicted from the cache
    // In a real system we would wait longer, but for testing we use a very short TTL
    let result = verifier.verify(&token1, htm, htu).await?;
    assert!(result.is_some(), "Token1 should work after cache eviction");
    
    Ok(())
}

#[tokio::test]
async fn test_key_pair_generation_and_thumbprint() -> BaffaoResult<()> {
    // Generate a key pair
    let key_pair = DPoPKeyPair::generate()?;
    
    // Check private key is generated
    assert!(!key_pair.private_key_pem.is_empty(), "Private key should be generated");
    
    // Get public JWK
    let public_jwk = key_pair.public_jwk()?;
    assert!(!public_jwk.is_empty(), "Public JWK should be generated");
    
    // Parse JWK
    let jwk: serde_json::Value = serde_json::from_str(&public_jwk)?;
    
    // Check required JWK fields
    assert!(jwk["kty"].is_string(), "JWK should have kty field");
    assert!(jwk["crv"].is_string(), "JWK should have crv field");
    assert!(jwk["x"].is_string(), "JWK should have x field");
    assert!(jwk["y"].is_string(), "JWK should have y field");
    
    // Get thumbprint
    let thumbprint = key_pair.thumbprint()?;
    assert!(!thumbprint.is_empty(), "Thumbprint should be generated");
    
    // Ensure thumbprint is consistent
    let thumbprint2 = key_pair.thumbprint()?;
    assert_eq!(thumbprint, thumbprint2, "Thumbprint should be deterministic");
    
    Ok(())
}