//! Redis implementation of TokenManager.

use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use redis::{AsyncCommands, Value};
use serde_json;

use crate::token::{AccessToken, RefreshToken, TokenManager};
use crate::error::{BaffaoError, BaffaoResult};
use super::keys::{access_token_key, refresh_token_key, token_search_index_key};
use super::pool::RedisPool;

/// Redis implementation of the TokenManager trait.
#[derive(Clone)]
pub struct RedisTokenManager {
    pool: RedisPool,
}

impl RedisTokenManager {
    /// Creates a new Redis token manager.
    pub fn new(pool: RedisPool) -> Self {
        Self { pool }
    }
    
    /// Calculates TTL for a token in seconds.
    fn calculate_ttl(expires_at: &DateTime<Utc>) -> i64 {
        let now = Utc::now();
        if *expires_at <= now {
            0 // Already expired
        } else {
            let duration = expires_at.signed_duration_since(now);
            duration.num_seconds().max(1) // Ensure at least 1 second
        }
    }
}

#[async_trait]
impl TokenManager for RedisTokenManager {
    async fn store_access_token(&self, user_id: &str, access_token: AccessToken) -> BaffaoResult<()> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        let mut redis_conn = conn.connection();
        
        let token_json = serde_json::to_string(&access_token)
            .map_err(|e| BaffaoError::Storage(format!("Failed to serialize access token: {}", e)))?;
            
        let token_key = access_token_key(user_id);
        let token_index_key = token_search_index_key(&access_token.token);
        let ttl = Self::calculate_ttl(&access_token.expires_at);
        
        // Use pipeline for efficiency
        redis::pipe()
            // Store token data
            .cmd("SET").arg(&token_key).arg(&token_json).ignore()
            // Create index for token lookup
            .cmd("SET").arg(&token_index_key).arg(user_id).ignore()
            // Set expiration
            .cmd("EXPIRE").arg(&token_key).arg(ttl).ignore()
            .cmd("EXPIRE").arg(&token_index_key).arg(ttl).ignore()
            .query_async(redis_conn).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to store access token in Redis: {}", e)))?;
            
        Ok(())
    }

    async fn get_access_token(&self, user_id: &str) -> BaffaoResult<Option<AccessToken>> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        let mut redis_conn = conn.connection();
        
        let token_key = access_token_key(user_id);
        let token_data: Option<String> = redis_conn.get(&token_key).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to get access token from Redis: {}", e)))?;
            
        match token_data {
            Some(data) => {
                let token: AccessToken = serde_json::from_str(&data)
                    .map_err(|e| BaffaoError::Storage(format!("Failed to deserialize access token: {}", e)))?;
                    
                if token.is_expired() {
                    // Delete expired token and its index
                    redis::pipe()
                        .cmd("DEL").arg(&token_key).ignore()
                        .cmd("DEL").arg(token_search_index_key(&token.token)).ignore()
                        .query_async(redis_conn).await
                        .map_err(|e| BaffaoError::Storage(format!("Failed to delete expired token: {}", e)))?;
                        
                    Ok(None)
                } else {
                    Ok(Some(token))
                }
            },
            None => Ok(None),
        }
    }

    async fn store_refresh_token(&self, user_id: &str, refresh_token: RefreshToken) -> BaffaoResult<()> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        let mut redis_conn = conn.connection();
        
        let token_json = serde_json::to_string(&refresh_token)
            .map_err(|e| BaffaoError::Storage(format!("Failed to serialize refresh token: {}", e)))?;
            
        let token_key = refresh_token_key(user_id);
        let token_index_key = token_search_index_key(&refresh_token.token);
        
        // Default refresh token expiry (30 days)
        let ttl = 30 * 24 * 60 * 60;
        
        // Use pipeline for efficiency
        redis::pipe()
            // Store token data
            .cmd("SET").arg(&token_key).arg(&token_json).ignore()
            // Create index for token lookup
            .cmd("SET").arg(&token_index_key).arg(user_id).ignore()
            // Set expiration (default 30 days)
            .cmd("EXPIRE").arg(&token_key).arg(ttl).ignore()
            .cmd("EXPIRE").arg(&token_index_key).arg(ttl).ignore()
            .query_async(redis_conn).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to store refresh token in Redis: {}", e)))?;
            
        Ok(())
    }

    async fn get_refresh_token(&self, user_id: &str) -> BaffaoResult<Option<RefreshToken>> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        let mut redis_conn = conn.connection();
        
        let token_key = refresh_token_key(user_id);
        let token_data: Option<String> = redis_conn.get(&token_key).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to get refresh token from Redis: {}", e)))?;
            
        match token_data {
            Some(data) => {
                let token: RefreshToken = serde_json::from_str(&data)
                    .map_err(|e| BaffaoError::Storage(format!("Failed to deserialize refresh token: {}", e)))?;
                
                Ok(Some(token))
            },
            None => Ok(None),
        }
    }
    
    async fn revoke_tokens(&self, user_id: &str) -> BaffaoResult<()> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        let mut redis_conn = conn.connection();
        
        // Get tokens to delete their indices
        let access_token_key = access_token_key(user_id);
        let refresh_token_key = refresh_token_key(user_id);
        
        // Get the access token to find its index
        let access_token_data: Option<String> = redis_conn.get(&access_token_key).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to get access token for revocation: {}", e)))?;
            
        if let Some(data) = access_token_data {
            let token: AccessToken = serde_json::from_str(&data)
                .map_err(|e| BaffaoError::Storage(format!("Failed to deserialize access token: {}", e)))?;
                
            // Delete the token index
            let _: () = redis_conn.del(token_search_index_key(&token.token)).await
                .map_err(|e| BaffaoError::Storage(format!("Failed to delete access token index: {}", e)))?;
        }
        
        // Get the refresh token to find its index
        let refresh_token_data: Option<String> = redis_conn.get(&refresh_token_key).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to get refresh token for revocation: {}", e)))?;
            
        if let Some(data) = refresh_token_data {
            let token: RefreshToken = serde_json::from_str(&data)
                .map_err(|e| BaffaoError::Storage(format!("Failed to deserialize refresh token: {}", e)))?;
                
            // Delete the token index
            let _: () = redis_conn.del(token_search_index_key(&token.token)).await
                .map_err(|e| BaffaoError::Storage(format!("Failed to delete refresh token index: {}", e)))?;
        }
        
        // Delete the tokens
        redis::pipe()
            .cmd("DEL").arg(&access_token_key).ignore()
            .cmd("DEL").arg(&refresh_token_key).ignore()
            .query_async(redis_conn).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to revoke tokens in Redis: {}", e)))?;
            
        Ok(())
    }
    
    async fn get_access_token_for_scope(&self, user_id: &str, required_scopes: &[String]) -> BaffaoResult<Option<AccessToken>> {
        // For Redis, we need to get the token and check scopes in-memory
        // since Redis doesn't have built-in array containment check
        let token = self.get_access_token(user_id).await?;
        
        if let Some(token) = token {
            if token.has_scopes(required_scopes) && !token.is_expired() {
                return Ok(Some(token));
            }
        }
        
        Ok(None)
    }
}