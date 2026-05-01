//! PostgreSQL implementation of SessionManager.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use cookie::Cookie;
use serde_json::Value;
use tokio_postgres::types::Json;

use crate::session::{CookieConfig, Session, SessionManager};
use crate::error::{BaffaoError, BaffaoResult};
use super::pool::PostgresPool;
use crate::storage::error::{StorageError, StorageResult};

/// PostgreSQL implementation of the SessionManager trait.
#[derive(Clone)]
pub struct PostgresSessionManager {
    pool: PostgresPool,
}

impl PostgresSessionManager {
    /// Creates a new PostgreSQL session manager.
    pub fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionManager for PostgresSessionManager {
    async fn create_session(&self, user_id: &str, duration: Option<Duration>) -> BaffaoResult<Session> {
        let session = Session::new(user_id.to_string(), duration);
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        
        // Convert Option<Value> to Json<Option<Value>> for PostgreSQL
        let data_json = session.data.as_ref().map(|d| Json(d.clone()));
        
        conn.connection().execute(
            "INSERT INTO baffao_sessions (id, user_id, created_at, expires_at, data, scopes) 
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &session.id,
                &session.user_id,
                &session.created_at,
                &session.expires_at,
                &data_json,
                &session.scopes,
            ]
        ).await.map_err(|e| {
            BaffaoError::Storage(format!("Failed to insert session: {}", e))
        })?;
        
        Ok(session)
    }
    
    async fn get_session(&self, session_id: &str) -> BaffaoResult<Option<Session>> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        
        let row = match conn.connection().query_opt(
            "SELECT id, user_id, created_at, expires_at, data, scopes FROM baffao_sessions WHERE id = $1",
            &[&session_id]
        ).await {
            Ok(row) => row,
            Err(e) => return Err(BaffaoError::Storage(format!("Failed to query session: {}", e))),
        };
        
        let session = match row {
            Some(row) => {
                let id: String = row.get(0);
                let user_id: String = row.get(1);
                let created_at: DateTime<Utc> = row.get(2);
                let expires_at: DateTime<Utc> = row.get(3);
                
                // Handle NULL data
                let data: Option<Json<Value>> = row.get(4);
                let data = data.map(|d| d.0);
                
                // Handle NULL scopes array
                let scopes: Option<Vec<String>> = row.get(5);
                
                let session = Session {
                    id,
                    user_id,
                    created_at,
                    expires_at,
                    data,
                    scopes,
                };
                
                if session.is_expired() {
                    // Delete expired session
                    let _ = conn.connection().execute(
                        "DELETE FROM baffao_sessions WHERE id = $1",
                        &[&session_id]
                    ).await;
                    None
                } else {
                    Some(session)
                }
            },
            None => None,
        };
        
        Ok(session)
    }
    
    async fn update_session(&self, session: &Session) -> BaffaoResult<()> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        
        // Convert Option<Value> to Json<Option<Value>> for PostgreSQL
        let data_json = session.data.as_ref().map(|d| Json(d.clone()));
        
        conn.connection().execute(
            "UPDATE baffao_sessions 
             SET user_id = $2, created_at = $3, expires_at = $4, data = $5, scopes = $6
             WHERE id = $1",
            &[
                &session.id,
                &session.user_id,
                &session.created_at,
                &session.expires_at,
                &data_json,
                &session.scopes,
            ]
        ).await.map_err(|e| {
            BaffaoError::Storage(format!("Failed to update session: {}", e))
        })?;
        
        Ok(())
    }
    
    async fn delete_session(&self, session_id: &str) -> BaffaoResult<()> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        
        conn.connection().execute(
            "DELETE FROM baffao_sessions WHERE id = $1",
            &[&session_id]
        ).await.map_err(|e| {
            BaffaoError::Storage(format!("Failed to delete session: {}", e))
        })?;
        
        Ok(())
    }
    
    fn create_cookie(&self, session: &Session, config: &CookieConfig) -> Cookie<'static> {
        let mut cookie = Cookie::new(config.name.clone(), session.id.clone());
        
        cookie.set_http_only(config.http_only);
        cookie.set_secure(config.secure);
        cookie.set_path(config.path.clone());
        cookie.set_same_site(config.same_site);
        
        if let Some(domain) = &config.domain {
            cookie.set_domain(domain.clone());
        }
        
        if let Some(max_age) = config.max_age {
            cookie.set_max_age(time::Duration::seconds(max_age));
        }
        
        cookie
    }
    
    fn session_id_from_cookie(&self, cookie_value: &str) -> BaffaoResult<String> {
        Ok(cookie_value.to_string())
    }
}