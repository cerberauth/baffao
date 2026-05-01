//! Redis storage backend implementation.
//!
//! This module provides a Redis implementation of the storage interfaces,
//! allowing session and token data to be stored in a Redis database.

mod pool;
mod session;
mod token;
mod keys;

pub use pool::{RedisPool, RedisConnection};
use self::session::RedisSessionManager;
use self::token::RedisTokenManager;

use crate::session::SessionManager;
use crate::token::TokenManager;
use super::pool::DatabaseConfig;
use super::error::{StorageError, StorageResult};

/// Redis backend for session and token storage.
#[derive(Clone)]
pub struct RedisBackend {
    pool: RedisPool,
    session_manager: RedisSessionManager,
    token_manager: RedisTokenManager,
}

impl RedisBackend {
    /// Creates a new Redis backend.
    pub async fn new(config: DatabaseConfig) -> StorageResult<Self> {
        let pool = RedisPool::new(config).await?;
        
        let session_manager = RedisSessionManager::new(pool.clone());
        let token_manager = RedisTokenManager::new(pool.clone());
        
        Ok(Self {
            pool,
            session_manager,
            token_manager,
        })
    }
    
    /// Gets the session manager.
    pub fn session_manager(&self) -> impl SessionManager {
        self.session_manager.clone()
    }
    
    /// Gets the token manager.
    pub fn token_manager(&self) -> impl TokenManager {
        self.token_manager.clone()
    }
    
    /// Checks the health of the database connection.
    pub async fn check_health(&self) -> StorageResult<()> {
        self.pool.check_health().await
    }
}