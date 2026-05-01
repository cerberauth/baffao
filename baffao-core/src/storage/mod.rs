//! Storage backends for persistent data storage.
//!
//! This module provides interfaces and implementations for storing session
//! and token data in various database backends.

mod error;
mod pool;
#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "redis")]
mod redis;

pub use error::{StorageError, StorageResult};
pub use pool::{ConnectionPool, DatabaseConfig, PooledConnection};
#[cfg(feature = "postgres")]
pub use postgres::PostgresBackend;
#[cfg(feature = "redis")]
pub use redis::RedisBackend;

pub mod prelude {
    pub use super::error::{StorageError, StorageResult};
    pub use super::pool::{ConnectionPool, DatabaseConfig, PooledConnection};
    #[cfg(feature = "postgres")]
    pub use super::postgres::PostgresBackend;
    #[cfg(feature = "redis")]
    pub use super::redis::RedisBackend;
}