//! Database connection pool abstraction.
//!
//! This module provides a generic interface for database connection pools,
//! allowing different implementations for various database backends.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::time::Duration;

use super::error::{StorageError, StorageResult};

/// Database configuration for connection pools.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    /// Database URL (connection string)
    pub url: String,
    
    /// Maximum number of connections in the pool
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    
    /// Minimum number of idle connections in the pool
    #[serde(default = "default_min_idle")]
    pub min_idle: Option<u32>,
    
    /// Connection timeout in seconds
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u64,
    
    /// Idle timeout in seconds
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_seconds: Option<u64>,
    
    /// Maximum lifetime of a connection in seconds
    #[serde(default = "default_max_lifetime")]
    pub max_lifetime_seconds: Option<u64>,
    
    /// Test query to ensure connection is still valid
    #[serde(default = "default_test_query")]
    pub test_query: Option<String>,
}

fn default_max_connections() -> u32 {
    10
}

fn default_min_idle() -> Option<u32> {
    Some(1)
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_idle_timeout() -> Option<u64> {
    Some(300)
}

fn default_max_lifetime() -> Option<u64> {
    Some(1800)
}

fn default_test_query() -> Option<String> {
    None
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            max_connections: default_max_connections(),
            min_idle: default_min_idle(),
            connect_timeout_seconds: default_connect_timeout(),
            idle_timeout_seconds: default_idle_timeout(),
            max_lifetime_seconds: default_max_lifetime(),
            test_query: default_test_query(),
        }
    }
}

/// Marker trait for connection types that can be pooled.
pub trait PoolableConnection: Send + Sync + 'static {}

/// Trait for pooled database connections.
pub trait PooledConnection: Send + Sync {
    /// The type of connection that is pooled.
    type Connection: PoolableConnection;
    
    /// Get the underlying connection.
    fn connection(&mut self) -> &mut Self::Connection;
}

/// Trait for database connection pools.
#[async_trait]
pub trait ConnectionPool: Send + Sync + Clone + 'static {
    /// The type of connection returned by the pool.
    type Connection: PooledConnection;
    
    /// Create a new connection pool with the given configuration.
    async fn new(config: DatabaseConfig) -> StorageResult<Self> where Self: Sized;
    
    /// Get a connection from the pool.
    async fn get(&self) -> StorageResult<Self::Connection>;
    
    /// Check the health of the connection pool.
    async fn check_health(&self) -> StorageResult<()>;
    
    /// Close the connection pool.
    async fn close(&self) -> StorageResult<()>;
    
    /// Get the configuration used to create the pool.
    fn config(&self) -> &DatabaseConfig;
}