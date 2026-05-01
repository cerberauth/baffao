//! Database migrations for PostgreSQL backend.

use crate::storage::error::{StorageError, StorageResult};
use super::pool::PostgresPool;

/// Runs all migrations to set up the PostgreSQL database schema.
pub async fn run_migrations(pool: &PostgresPool) -> StorageResult<()> {
    let conn = pool.get().await?;
    let transaction = conn.connection().transaction().await
        .map_err(|e| StorageError::Transaction(format!("Failed to start transaction: {}", e)))?;
    
    // Create migrations table if it doesn't exist
    transaction.execute(
        "CREATE TABLE IF NOT EXISTS baffao_migrations (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        )",
        &[]
    ).await.map_err(|e| StorageError::Migration(format!("Failed to create migrations table: {}", e)))?;

    // Define migrations
    let migrations = vec![
        ("001_initial_schema", create_initial_schema()),
        ("002_add_token_indexes", add_token_indexes()),
    ];
    
    // Apply migrations
    for (name, sql) in migrations {
        // Check if migration has already been applied
        let already_applied = transaction
            .query_one("SELECT COUNT(*) FROM baffao_migrations WHERE name = $1", &[&name])
            .await
            .map_err(|e| StorageError::Migration(format!("Failed to check migration status: {}", e)))?
            .get::<_, i64>(0) > 0;
            
        if already_applied {
            continue;
        }
        
        // Apply the migration
        transaction.batch_execute(sql)
            .await
            .map_err(|e| StorageError::Migration(format!("Failed to apply migration {}: {}", name, e)))?;
            
        // Record the migration
        transaction.execute(
            "INSERT INTO baffao_migrations (name) VALUES ($1)",
            &[&name]
        ).await.map_err(|e| StorageError::Migration(format!("Failed to record migration: {}", e)))?;
    }
    
    // Commit the transaction
    transaction.commit().await
        .map_err(|e| StorageError::Transaction(format!("Failed to commit transaction: {}", e)))?;
        
    Ok(())
}

/// Creates the initial database schema.
fn create_initial_schema() -> &'static str {
    r#"
    -- Sessions table
    CREATE TABLE IF NOT EXISTS baffao_sessions (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        data JSONB,
        scopes TEXT[]
    );
    
    CREATE INDEX IF NOT EXISTS baffao_sessions_user_id_idx ON baffao_sessions(user_id);
    CREATE INDEX IF NOT EXISTS baffao_sessions_expires_at_idx ON baffao_sessions(expires_at);
    
    -- Access tokens table
    CREATE TABLE IF NOT EXISTS baffao_access_tokens (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        token TEXT NOT NULL,
        issued_at TIMESTAMP WITH TIME ZONE NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        scopes TEXT[]
    );
    
    CREATE UNIQUE INDEX IF NOT EXISTS baffao_access_tokens_user_id_idx ON baffao_access_tokens(user_id);
    
    -- Refresh tokens table
    CREATE TABLE IF NOT EXISTS baffao_refresh_tokens (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        token TEXT NOT NULL,
        issued_at TIMESTAMP WITH TIME ZONE NOT NULL
    );
    
    CREATE UNIQUE INDEX IF NOT EXISTS baffao_refresh_tokens_user_id_idx ON baffao_refresh_tokens(user_id);
    "#
}

/// Adds indexes to improve performance.
fn add_token_indexes() -> &'static str {
    r#"
    -- Add indexes for token lookup
    CREATE INDEX IF NOT EXISTS baffao_access_tokens_token_idx ON baffao_access_tokens(token);
    CREATE INDEX IF NOT EXISTS baffao_refresh_tokens_token_idx ON baffao_refresh_tokens(token);
    
    -- Add index for expired tokens
    CREATE INDEX IF NOT EXISTS baffao_access_tokens_expires_at_idx ON baffao_access_tokens(expires_at);
    "#
}