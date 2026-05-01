//! PostgreSQL migrations functionality.

use std::path::Path;
use tokio_postgres::Transaction;

use crate::storage::error::{StorageError, StorageResult};

/// Represents a single database migration.
pub struct Migration {
    /// Unique name of the migration
    pub name: &'static str,
    
    /// SQL content to run for the migration
    pub sql: &'static str,
    
    /// Optional description
    pub description: Option<&'static str>,
}

/// Runs a list of migrations against a PostgreSQL database.
pub async fn run_migrations(
    transaction: &Transaction<'_>,
    migrations: &[Migration],
) -> StorageResult<()> {
    // Create migrations table if it doesn't exist
    transaction.execute(
        "CREATE TABLE IF NOT EXISTS baffao_migrations (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL UNIQUE,
            applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            description TEXT
        )",
        &[],
    ).await.map_err(|e| 
        StorageError::Migration(format!("Failed to create migrations table: {}", e))
    )?;

    // Get already applied migrations
    let rows = transaction.query(
        "SELECT name FROM baffao_migrations ORDER BY id",
        &[],
    ).await.map_err(|e|
        StorageError::Migration(format!("Failed to query applied migrations: {}", e))
    )?;

    let applied_migrations: Vec<String> = rows.iter()
        .map(|row| row.get(0))
        .collect();

    // Apply pending migrations
    for migration in migrations {
        if applied_migrations.contains(&migration.name.to_string()) {
            continue; // Skip already applied migrations
        }

        // Apply the migration
        transaction.batch_execute(migration.sql).await.map_err(|e|
            StorageError::Migration(format!("Failed to apply migration {}: {}", migration.name, e))
        )?;

        // Record the migration
        transaction.execute(
            "INSERT INTO baffao_migrations (name, description) VALUES ($1, $2)",
            &[&migration.name, &migration.description],
        ).await.map_err(|e|
            StorageError::Migration(format!("Failed to record migration {}: {}", migration.name, e))
        )?;
    }

    Ok(())
}

/// Reads SQL migrations from files in a directory.
///
/// Files should be named in the format: `NNN_name.sql` where NNN is a number
/// indicating the ordering of migrations.
pub async fn read_migrations_from_dir(dir_path: &Path) -> StorageResult<Vec<Migration>> {
    let mut migrations = Vec::new();
    
    // Read directory
    let entries = std::fs::read_dir(dir_path)
        .map_err(|e| StorageError::Migration(format!("Failed to read migrations directory: {}", e)))?;
    
    // Process SQL files
    for entry in entries {
        let entry = entry.map_err(|e| 
            StorageError::Migration(format!("Failed to read directory entry: {}", e))
        )?;
        
        let path = entry.path();
        
        // Skip non-SQL files
        if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("sql") {
            continue;
        }
        
        // Get filename
        let file_name = path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| 
                StorageError::Migration("Failed to get migration file name".to_string())
            )?;
            
        // Read file content
        let sql = std::fs::read_to_string(&path)
            .map_err(|e| 
                StorageError::Migration(format!("Failed to read migration file {}: {}", file_name, e))
            )?;
            
        // Create migration
        migrations.push(Migration {
            name: Box::leak(file_name.to_string().into_boxed_str()),
            sql: Box::leak(sql.into_boxed_str()),
            description: None,
        });
    }
    
    // Sort migrations by filename
    migrations.sort_by(|a, b| a.name.cmp(b.name));
    
    Ok(migrations)
}