//! PostgreSQL storage backend implementation.
//!
//! This module provides a PostgreSQL implementation of the storage interfaces,
//! allowing session and token data to be stored in a PostgreSQL database.

mod pool;
mod session;
mod token;
mod migrations;

pub use pool::{PostgresPool, PostgresConnection};
use self::session::PostgresSessionManager;
use self::token::PostgresTokenManager;

use crate::session::SessionManager;
use crate::token::TokenManager;
use super::pool::DatabaseConfig;
use super::error::{StorageError, StorageResult};

/// PostgreSQL backend for session and token storage.
#[derive(Clone)]
pub struct PostgresBackend {
    pool: PostgresPool,
    session_manager: PostgresSessionManager,
    token_manager: PostgresTokenManager,
}

impl PostgresBackend {
    /// Creates a new PostgreSQL backend.
    pub async fn new(config: DatabaseConfig) -> StorageResult<Self> {
        let pool = PostgresPool::new(config).await?;
        
        // Run migrations to ensure tables exist
        migrations::run_migrations(&pool).await?;
        
        let session_manager = PostgresSessionManager::new(pool.clone());
        let token_manager = PostgresTokenManager::new(pool.clone());
        
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