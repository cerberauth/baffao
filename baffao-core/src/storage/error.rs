//! Error types for storage operations.

use std::fmt;

use crate::error::BaffaoError;

/// Error type for storage operations.
#[derive(Debug)]
pub enum StorageError {
    /// Connection error
    Connection(String),

    /// Query execution error
    Query(String),

    /// Data serialization/deserialization error
    Serialization(String),

    /// Pool error
    Pool(String),

    /// Migration error
    Migration(String),

    /// Not found error
    NotFound(String),

    /// Validation error
    Validation(String),

    /// Transaction error
    Transaction(String),

    /// Configuration error
    Configuration(String),

    /// Generic error
    Other(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Connection(msg) => write!(f, "Storage connection error: {}", msg),
            StorageError::Query(msg) => write!(f, "Storage query error: {}", msg),
            StorageError::Serialization(msg) => write!(f, "Storage serialization error: {}", msg),
            StorageError::Pool(msg) => write!(f, "Storage pool error: {}", msg),
            StorageError::Migration(msg) => write!(f, "Storage migration error: {}", msg),
            StorageError::NotFound(msg) => write!(f, "Storage not found: {}", msg),
            StorageError::Validation(msg) => write!(f, "Storage validation error: {}", msg),
            StorageError::Transaction(msg) => write!(f, "Storage transaction error: {}", msg),
            StorageError::Configuration(msg) => write!(f, "Storage configuration error: {}", msg),
            StorageError::Other(msg) => write!(f, "Storage error: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<StorageError> for BaffaoError {
    fn from(err: StorageError) -> Self {
        BaffaoError::Storage(err.to_string())
    }
}

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;
