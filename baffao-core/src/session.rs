//! Session management for OAuth 2.0 flows.
//!
//! This module provides functionality for managing user sessions,
//! including creation, validation, and storage.

use std::fmt::Debug;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{BaffaoError, BaffaoResult};

/// Represents a user session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier
    pub id: String,
    /// Associated user identifier
    pub user_id: String,
    /// When the session was created
    pub created_at: DateTime<Utc>,
    /// When the session expires
    pub expires_at: DateTime<Utc>,
    /// Optional additional data
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Optional additional scopes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
}

/// Session cookie configuration
#[derive(Debug, Clone)]
pub struct CookieConfig {
    /// Name of the cookie
    pub name: String,
    /// Domain of the cookie (optional)
    pub domain: Option<String>,
    /// Path of the cookie
    pub path: String,
    /// Whether the cookie is secure (HTTPS only)
    pub secure: bool,
    /// Whether the cookie is HTTP only
    pub http_only: bool,
    /// SameSite attribute of the cookie
    pub same_site: SameSite,
    /// Max age of the cookie in seconds
    pub max_age: Option<i64>,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "__Host-baffao-session".to_string(),
            domain: None,
            path: "/".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Strict,
            max_age: Some(3600 * 24), // 24 hours
        }
    }
}

impl Session {
    /// Creates a new session
    pub fn new(user_id: String, duration: Option<Duration>) -> Self {
        let created_at = Utc::now();
        let expires_at = created_at + duration.unwrap_or_else(|| Duration::hours(24));

        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            created_at,
            expires_at,
            data: None,
            scopes: None,
        }
    }

    /// Checks if the session is expired
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }

    /// Extends the session by the specified duration
    pub fn extend(&mut self, duration: Duration) {
        self.expires_at = Utc::now() + duration;
    }

    /// Sets additional data on the session
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
    
    /// Sets scopes on the session
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = Some(scopes);
        self
    }
}

/// Trait for session storage and management
#[async_trait]
pub trait SessionManager: Send + Sync {
    /// Creates a new session
    async fn create_session(&self, user_id: &str, duration: Option<Duration>) -> BaffaoResult<Session>;
    
    /// Retrieves a session by ID
    async fn get_session(&self, session_id: &str) -> BaffaoResult<Option<Session>>;
    
    /// Updates a session
    async fn update_session(&self, session: &Session) -> BaffaoResult<()>;
    
    /// Deletes a session
    async fn delete_session(&self, session_id: &str) -> BaffaoResult<()>;
    
    /// Creates a cookie for the session
    fn create_cookie(&self, session: &Session, config: &CookieConfig) -> Cookie<'static>;
    
    /// Creates a session ID from a cookie value
    fn session_id_from_cookie(&self, cookie_value: &str) -> BaffaoResult<String>;
}

/// In-memory implementation of SessionManager for testing and simple cases
#[derive(Default)]
pub struct InMemorySessionManager {
    sessions: tokio::sync::Mutex<std::collections::HashMap<String, Session>>,
}

impl InMemorySessionManager {
    /// Creates a new in-memory session manager
    pub fn new() -> Self {
        Self {
            sessions: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[async_trait]
impl SessionManager for InMemorySessionManager {
    async fn create_session(&self, user_id: &str, duration: Option<Duration>) -> BaffaoResult<Session> {
        let session = Session::new(user_id.to_string(), duration);
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session.id.clone(), session.clone());
        Ok(session)
    }
    
    async fn get_session(&self, session_id: &str) -> BaffaoResult<Option<Session>> {
        let sessions = self.sessions.lock().await;
        let session = sessions.get(session_id).cloned();
        
        if let Some(session) = &session {
            if session.is_expired() {
                return Ok(None);
            }
        }
        
        Ok(session)
    }
    
    async fn update_session(&self, session: &Session) -> BaffaoResult<()> {
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session.id.clone(), session.clone());
        Ok(())
    }
    
    async fn delete_session(&self, session_id: &str) -> BaffaoResult<()> {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(session_id);
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