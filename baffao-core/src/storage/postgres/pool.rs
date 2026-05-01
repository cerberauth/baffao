//! PostgreSQL connection pool implementation.

use async_trait::async_trait;
use deadpool_postgres::{Client, Config, Pool, PoolError, Runtime};
use tokio_postgres::NoTls;

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::pool::{ConnectionPool, DatabaseConfig, PoolableConnection, PooledConnection};

/// PostgreSQL connection type.
pub struct PostgresConnection {
    client: Client,
}

impl PoolableConnection for Client {}

impl PooledConnection for PostgresConnection {
    type Connection = Client;
    
    fn connection(&mut self) -> &mut Self::Connection {
        &mut self.client
    }
}

/// PostgreSQL connection pool.
#[derive(Clone)]
pub struct PostgresPool {
    pool: Pool,
    config: DatabaseConfig,
}

#[async_trait]
impl ConnectionPool for PostgresPool {
    type Connection = PostgresConnection;
    
    async fn new(config: DatabaseConfig) -> StorageResult<Self> {
        let mut pg_config = Config::new();
        
        // Parse database URL
        pg_config.url = Some(config.url.clone());
        
        // Set pool configuration
        pg_config.max_size = config.max_connections as usize;
        
        if let Some(idle) = config.min_idle {
            pg_config.min_idle = Some(idle as usize);
        }
        
        // Create the pool
        let pool = pg_config.create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|e| StorageError::Pool(e.to_string()))?;
        
        // Test the connection
        let client = pool.get().await
            .map_err(|e| StorageError::Connection(format!("Failed to connect to PostgreSQL: {}", e)))?;
        
        // Run a simple query to ensure the connection works
        client.query("SELECT 1", &[]).await
            .map_err(|e| StorageError::Query(format!("Failed to execute test query: {}", e)))?;
        
        Ok(Self { pool, config })
    }
    
    async fn get(&self) -> StorageResult<Self::Connection> {
        let client = self.pool.get().await
            .map_err(|e| match e {
                PoolError::Timeout => StorageError::Connection("Connection pool timeout".to_string()),
                _ => StorageError::Connection(format!("Failed to get connection from pool: {}", e)),
            })?;
            
        Ok(PostgresConnection { client })
    }
    
    async fn check_health(&self) -> StorageResult<()> {
        let conn = self.get().await?;
        
        conn.connection().query("SELECT 1", &[]).await
            .map_err(|e| StorageError::Query(format!("Health check failed: {}", e)))?;
            
        Ok(())
    }
    
    async fn close(&self) -> StorageResult<()> {
        self.pool.close();
        Ok(())
    }
    
    fn config(&self) -> &DatabaseConfig {
        &self.config
    }
}