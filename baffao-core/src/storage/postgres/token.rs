//! PostgreSQL implementation of TokenManager.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::token::{AccessToken, RefreshToken, TokenManager};
use crate::error::{BaffaoError, BaffaoResult};
use super::pool::PostgresPool;

/// PostgreSQL implementation of the TokenManager trait.
#[derive(Clone)]
pub struct PostgresTokenManager {
    pool: PostgresPool,
}

impl PostgresTokenManager {
    /// Creates a new PostgreSQL token manager.
    pub fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl TokenManager for PostgresTokenManager {
    async fn store_access_token(&self, user_id: &str, access_token: AccessToken) -> BaffaoResult<()> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        
        // First try to update any existing token for this user
        let updated = conn.connection().execute(
            "UPDATE baffao_access_tokens 
             SET token = $1, issued_at = $2, expires_at = $3, scopes = $4
             WHERE user_id = $5",
            &[
                &access_token.token,
                &access_token.issued_at,
                &access_token.expires_at,
                &access_token.scopes,
                &user_id,
            ]
        ).await.map_err(|e| {
            BaffaoError::Storage(format!("Failed to update access token: {}", e))
        })?;
        
        // If no rows were updated, insert a new one
        if updated == 0 {
            conn.connection().execute(
                "INSERT INTO baffao_access_tokens (user_id, token, issued_at, expires_at, scopes) 
                 VALUES ($1, $2, $3, $4, $5)",
                &[
                    &user_id,
                    &access_token.token,
                    &access_token.issued_at,
                    &access_token.expires_at,
                    &access_token.scopes,
                ]
            ).await.map_err(|e| {
                BaffaoError::Storage(format!("Failed to insert access token: {}", e))
            })?;
        }
        
        Ok(())
    }

    async fn get_access_token(&self, user_id: &str) -> BaffaoResult<Option<AccessToken>> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        
        let row = match conn.connection().query_opt(
            "SELECT token, issued_at, expires_at, scopes FROM baffao_access_tokens WHERE user_id = $1",
            &[&user_id]
        ).await {
            Ok(row) => row,
            Err(e) => return Err(BaffaoError::Storage(format!("Failed to query access token: {}", e))),
        };
        
        let token = match row {
            Some(row) => {
                let token: String = row.get(0);
                let issued_at: DateTime<Utc> = row.get(1);
                let expires_at: DateTime<Utc> = row.get(2);
                let scopes: Option<Vec<String>> = row.get(3);
                
                let token = AccessToken {
                    token,
                    issued_at,
                    expires_at,
                    scopes,
                };
                
                if token.is_expired() {
                    // Optionally delete expired token
                    // let _ = conn.connection().execute(
                    //     "DELETE FROM baffao_access_tokens WHERE user_id = $1",
                    //     &[&user_id]
                    // ).await;
                    None
                } else {
                    Some(token)
                }
            },
            None => None,
        };
        
        Ok(token)
    }

    async fn store_refresh_token(&self, user_id: &str, refresh_token: RefreshToken) -> BaffaoResult<()> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        
        // First try to update any existing token for this user
        let updated = conn.connection().execute(
            "UPDATE baffao_refresh_tokens 
             SET token = $1, issued_at = $2
             WHERE user_id = $3",
            &[
                &refresh_token.token,
                &refresh_token.issued_at,
                &user_id,
            ]
        ).await.map_err(|e| {
            BaffaoError::Storage(format!("Failed to update refresh token: {}", e))
        })?;
        
        // If no rows were updated, insert a new one
        if updated == 0 {
            conn.connection().execute(
                "INSERT INTO baffao_refresh_tokens (user_id, token, issued_at) 
                 VALUES ($1, $2, $3)",
                &[
                    &user_id,
                    &refresh_token.token,
                    &refresh_token.issued_at,
                ]
            ).await.map_err(|e| {
                BaffaoError::Storage(format!("Failed to insert refresh token: {}", e))
            })?;
        }
        
        Ok(())
    }

    async fn get_refresh_token(&self, user_id: &str) -> BaffaoResult<Option<RefreshToken>> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        
        let row = match conn.connection().query_opt(
            "SELECT token, issued_at FROM baffao_refresh_tokens WHERE user_id = $1",
            &[&user_id]
        ).await {
            Ok(row) => row,
            Err(e) => return Err(BaffaoError::Storage(format!("Failed to query refresh token: {}", e))),
        };
        
        let token = match row {
            Some(row) => {
                let token: String = row.get(0);
                let issued_at: DateTime<Utc> = row.get(1);
                
                Some(RefreshToken {
                    token,
                    issued_at,
                })
            },
            None => None,
        };
        
        Ok(token)
    }
    
    async fn revoke_tokens(&self, user_id: &str) -> BaffaoResult<()> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        
        // Start transaction
        let transaction = conn.connection().transaction().await
            .map_err(|e| BaffaoError::Storage(format!("Failed to start transaction: {}", e)))?;
            
        // Delete access tokens
        transaction.execute(
            "DELETE FROM baffao_access_tokens WHERE user_id = $1",
            &[&user_id]
        ).await.map_err(|e| {
            BaffaoError::Storage(format!("Failed to delete access tokens: {}", e))
        })?;
        
        // Delete refresh tokens
        transaction.execute(
            "DELETE FROM baffao_refresh_tokens WHERE user_id = $1",
            &[&user_id]
        ).await.map_err(|e| {
            BaffaoError::Storage(format!("Failed to delete refresh tokens: {}", e))
        })?;
        
        // Commit transaction
        transaction.commit().await.map_err(|e| {
            BaffaoError::Storage(format!("Failed to commit transaction: {}", e))
        })?;
        
        Ok(())
    }
    
    async fn get_access_token_for_scope(&self, user_id: &str, required_scopes: &[String]) -> BaffaoResult<Option<AccessToken>> {
        // Implement optimized query that directly checks for scopes in database
        if required_scopes.is_empty() {
            // If no scopes are required, just get the regular token
            return self.get_access_token(user_id).await;
        }
        
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        
        // Convert required_scopes to a Postgres array for the query
        let scopes_array: Vec<&str> = required_scopes.iter().map(|s| s.as_str()).collect();
        
        // Query that checks if token is not expired and all required scopes are contained in token scopes
        let row = match conn.connection().query_opt(
            "SELECT token, issued_at, expires_at, scopes 
             FROM baffao_access_tokens 
             WHERE user_id = $1 
               AND expires_at > NOW() 
               AND scopes @> $2::text[]",
            &[&user_id, &scopes_array]
        ).await {
            Ok(row) => row,
            Err(e) => return Err(BaffaoError::Storage(format!("Failed to query scoped access token: {}", e))),
        };
        
        let token = match row {
            Some(row) => {
                let token: String = row.get(0);
                let issued_at: DateTime<Utc> = row.get(1);
                let expires_at: DateTime<Utc> = row.get(2);
                let scopes: Option<Vec<String>> = row.get(3);
                
                Some(AccessToken {
                    token,
                    issued_at,
                    expires_at,
                    scopes,
                })
            },
            None => None,
        };
        
        Ok(token)
    }
}