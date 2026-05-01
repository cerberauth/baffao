//! Redis connection pool implementation.

use async_trait::async_trait;
use deadpool_redis::{Config, Connection, Pool, Runtime};
use redis::{Client, RedisError};

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::pool::{ConnectionPool, DatabaseConfig, PoolableConnection, PooledConnection};

/// Redis connection type.
pub struct RedisConnection {
    conn: Connection,
}

impl PoolableConnection for Connection {}

impl PooledConnection for RedisConnection {
    type Connection = Connection;
    
    fn connection(&mut self) -> &mut Self::Connection {
        &mut self.conn
    }
}

/// Redis connection pool.
#[derive(Clone)]
pub struct RedisPool {
    pool: Pool,
    config: DatabaseConfig,
}

#[async_trait]
impl ConnectionPool for RedisPool {
    type Connection = RedisConnection;
    
    async fn new(config: DatabaseConfig) -> StorageResult<Self> {
        let redis_url = config.url.clone();
        
        // Create Redis client
        let client = Client::open(redis_url.as_str())
            .map_err(|e| StorageError::Connection(format!("Failed to create Redis client: {}", e)))?;
            
        // Verify connection
        let mut con = client.get_async_connection().await
            .map_err(|e| StorageError::Connection(format!("Failed to connect to Redis: {}", e)))?;
            
        let _: String = redis::cmd("PING")
            .query_async(&mut con).await
            .map_err(|e| StorageError::Query(format!("Failed to ping Redis: {}", e)))?;
        
        // Create pool
        let mut cfg = Config::from_url(redis_url);
        cfg.max_size = config.max_connections;
        
        let pool = cfg.create_pool(Some(Runtime::Tokio1))
            .map_err(|e| StorageError::Pool(format!("Failed to create Redis connection pool: {}", e)))?;
        
        Ok(Self { pool, config })
    }
    
    async fn get(&self) -> StorageResult<Self::Connection> {
        self.pool.get().await
            .map(|conn| RedisConnection { conn })
            .map_err(|e| {
                match e {
                    deadpool_redis::PoolError::Timeout(_) => {
                        StorageError::Connection("Connection pool timeout".to_string())
                    },
                    _ => StorageError::Connection(format!("Failed to get connection from pool: {}", e)),
                }
            })
    }
    
    async fn check_health(&self) -> StorageResult<()> {
        let mut conn = self.get().await?;
        
        redis::cmd("PING")
            .query_async::<_, String>(conn.connection()).await
            .map_err(|e| StorageError::Query(format!("Health check failed: {}", e)))?;
            
        Ok(())
    }
    
    async fn close(&self) -> StorageResult<()> {
        // Redis pool doesn't have an explicit close method
        // but we can clear it
        self.pool.resize(0);
        Ok(())
    }
    
    fn config(&self) -> &DatabaseConfig {
        &self.config
    }
}