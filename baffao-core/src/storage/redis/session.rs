//! Redis implementation of SessionManager.

use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use cookie::Cookie;
use redis::{AsyncCommands, Value};
use serde_json;

use crate::session::{CookieConfig, Session, SessionManager};
use crate::error::{BaffaoError, BaffaoResult};
use super::keys::{session_key, user_sessions_key};
use super::pool::RedisPool;

/// Redis implementation of the SessionManager trait.
#[derive(Clone)]
pub struct RedisSessionManager {
    pool: RedisPool,
}

impl RedisSessionManager {
    /// Creates a new Redis session manager.
    pub fn new(pool: RedisPool) -> Self {
        Self { pool }
    }
    
    /// Calculates TTL for a session in seconds.
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
impl SessionManager for RedisSessionManager {
    async fn create_session(&self, user_id: &str, duration: Option<Duration>) -> BaffaoResult<Session> {
        let session = Session::new(user_id.to_string(), duration);
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        let mut redis_conn = conn.connection();
        
        let session_json = serde_json::to_string(&session)
            .map_err(|e| BaffaoError::Storage(format!("Failed to serialize session: {}", e)))?;
            
        let session_key = session_key(&session.id);
        let user_sessions_key = user_sessions_key(user_id);
        let ttl = Self::calculate_ttl(&session.expires_at);
        
        // Use pipeline for efficiency
        redis::pipe()
            // Store session data
            .cmd("SET").arg(&session_key).arg(session_json).ignore()
            // Add session ID to user's sessions set
            .cmd("SADD").arg(&user_sessions_key).arg(&session.id).ignore()
            // Set expiration
            .cmd("EXPIRE").arg(&session_key).arg(ttl).ignore()
            .cmd("EXPIRE").arg(&user_sessions_key).arg(ttl).ignore()
            .query_async(redis_conn).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to store session in Redis: {}", e)))?;
            
        Ok(session)
    }
    
    async fn get_session(&self, session_id: &str) -> BaffaoResult<Option<Session>> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        let mut redis_conn = conn.connection();
        
        let session_key = session_key(session_id);
        let session_data: Option<String> = redis_conn.get(&session_key).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to get session from Redis: {}", e)))?;
            
        match session_data {
            Some(data) => {
                let session: Session = serde_json::from_str(&data)
                    .map_err(|e| BaffaoError::Storage(format!("Failed to deserialize session: {}", e)))?;
                    
                if session.is_expired() {
                    // Delete expired session
                    let _: () = redis_conn.del(&session_key).await
                        .map_err(|e| BaffaoError::Storage(format!("Failed to delete expired session: {}", e)))?;
                        
                    // Remove from user's sessions set
                    let _: () = redis_conn.srem(user_sessions_key(&session.user_id), &session.id).await
                        .map_err(|e| BaffaoError::Storage(format!("Failed to remove session from user's set: {}", e)))?;
                        
                    Ok(None)
                } else {
                    Ok(Some(session))
                }
            },
            None => Ok(None),
        }
    }
    
    async fn update_session(&self, session: &Session) -> BaffaoResult<()> {
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        let mut redis_conn = conn.connection();
        
        let session_json = serde_json::to_string(session)
            .map_err(|e| BaffaoError::Storage(format!("Failed to serialize session: {}", e)))?;
            
        let session_key = session_key(&session.id);
        let ttl = Self::calculate_ttl(&session.expires_at);
        
        // Store session data with updated expiry
        let _: () = redis_conn.set_ex(&session_key, session_json, ttl as usize).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to update session in Redis: {}", e)))?;
            
        // Update user sessions set expiry
        let user_sessions_key = user_sessions_key(&session.user_id);
        let _: () = redis_conn.expire(user_sessions_key, ttl as usize).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to update user sessions expiry: {}", e)))?;
            
        Ok(())
    }
    
    async fn delete_session(&self, session_id: &str) -> BaffaoResult<()> {
        // First get the session to determine the user ID
        let session = match self.get_session(session_id).await? {
            Some(s) => s,
            None => return Ok(()),  // Session already doesn't exist
        };
        
        let mut conn = self.pool.get().await.map_err(|e| BaffaoError::Storage(e.to_string()))?;
        let mut redis_conn = conn.connection();
        
        let session_key = session_key(session_id);
        
        // Delete the session and remove from user's sessions set
        redis::pipe()
            .cmd("DEL").arg(&session_key).ignore()
            .cmd("SREM").arg(user_sessions_key(&session.user_id)).arg(session_id).ignore()
            .query_async(redis_conn).await
            .map_err(|e| BaffaoError::Storage(format!("Failed to delete session from Redis: {}", e)))?;
            
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