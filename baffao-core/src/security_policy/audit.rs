//! Audit logging for security events.
//!
//! This module provides audit logging functionality for security events,
//! allowing for compliance tracking and security monitoring.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Mutex;

use crate::error::{BaffaoError, BaffaoResult};

/// Audit event severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditLevel {
    /// Informational event
    Info,
    /// Warning event
    Warning,
    /// Error event
    Error,
    /// Security alert
    Alert,
    /// Critical security event
    Critical,
}

impl ToString for AuditLevel {
    fn to_string(&self) -> String {
        match self {
            AuditLevel::Info => "INFO",
            AuditLevel::Warning => "WARNING",
            AuditLevel::Error => "ERROR",
            AuditLevel::Alert => "ALERT",
            AuditLevel::Critical => "CRITICAL",
        }.to_string()
    }
}

/// Audit event for security operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Severity level of the event
    pub level: AuditLevel,
    /// Event category
    pub category: String,
    /// Event type
    pub event_type: String,
    /// Event message
    pub message: String,
    /// User ID related to the event (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// Client ID related to the event (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// IP address related to the event (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// Session ID related to the event (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Additional data related to the event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// Outcome of the event
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

impl AuditEvent {
    /// Creates a new audit event.
    pub fn new(
        level: AuditLevel,
        category: String,
        event_type: String,
        message: String,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            category,
            event_type,
            message,
            user_id: None,
            client_id: None,
            ip_address: None,
            session_id: None,
            data: None,
            outcome: None,
        }
    }
    
    /// Sets the user ID.
    pub fn with_user_id(mut self, user_id: String) -> Self {
        self.user_id = Some(user_id);
        self
    }
    
    /// Sets the client ID.
    pub fn with_client_id(mut self, client_id: String) -> Self {
        self.client_id = Some(client_id);
        self
    }
    
    /// Sets the IP address.
    pub fn with_ip_address(mut self, ip_address: String) -> Self {
        self.ip_address = Some(ip_address);
        self
    }
    
    /// Sets the session ID.
    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }
    
    /// Sets additional data.
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }
    
    /// Sets the outcome.
    pub fn with_outcome(mut self, outcome: String) -> Self {
        self.outcome = Some(outcome);
        self
    }
    
    /// Creates a new informational audit event.
    pub fn info(category: String, event_type: String, message: String) -> Self {
        Self::new(AuditLevel::Info, category, event_type, message)
    }
    
    /// Creates a new warning audit event.
    pub fn warning(category: String, event_type: String, message: String) -> Self {
        Self::new(AuditLevel::Warning, category, event_type, message)
    }
    
    /// Creates a new error audit event.
    pub fn error(category: String, event_type: String, message: String) -> Self {
        Self::new(AuditLevel::Error, category, event_type, message)
    }
    
    /// Creates a new security alert audit event.
    pub fn alert(category: String, event_type: String, message: String) -> Self {
        Self::new(AuditLevel::Alert, category, event_type, message)
    }
    
    /// Creates a new critical audit event.
    pub fn critical(category: String, event_type: String, message: String) -> Self {
        Self::new(AuditLevel::Critical, category, event_type, message)
    }
}

/// Interface for audit logging.
#[async_trait]
pub trait AuditLogger: Send + Sync {
    /// Log an audit event.
    async fn log(&self, event: AuditEvent) -> BaffaoResult<()>;
    
    /// Log an informational event.
    async fn info(
        &self,
        category: String,
        event_type: String,
        message: String,
        context: Option<serde_json::Value>,
    ) -> BaffaoResult<()> {
        let event = AuditEvent::info(category, event_type, message);
        let event = if let Some(context) = context {
            event.with_data(context)
        } else {
            event
        };
        self.log(event).await
    }
    
    /// Log a warning event.
    async fn warning(
        &self,
        category: String,
        event_type: String,
        message: String,
        context: Option<serde_json::Value>,
    ) -> BaffaoResult<()> {
        let event = AuditEvent::warning(category, event_type, message);
        let event = if let Some(context) = context {
            event.with_data(context)
        } else {
            event
        };
        self.log(event).await
    }
    
    /// Log an error event.
    async fn error(
        &self,
        category: String,
        event_type: String,
        message: String,
        context: Option<serde_json::Value>,
    ) -> BaffaoResult<()> {
        let event = AuditEvent::error(category, event_type, message);
        let event = if let Some(context) = context {
            event.with_data(context)
        } else {
            event
        };
        self.log(event).await
    }
    
    /// Log a security alert.
    async fn alert(
        &self,
        category: String,
        event_type: String,
        message: String,
        context: Option<serde_json::Value>,
    ) -> BaffaoResult<()> {
        let event = AuditEvent::alert(category, event_type, message);
        let event = if let Some(context) = context {
            event.with_data(context)
        } else {
            event
        };
        self.log(event).await
    }
    
    /// Log a critical security event.
    async fn critical(
        &self,
        category: String,
        event_type: String,
        message: String,
        context: Option<serde_json::Value>,
    ) -> BaffaoResult<()> {
        let event = AuditEvent::critical(category, event_type, message);
        let event = if let Some(context) = context {
            event.with_data(context)
        } else {
            event
        };
        self.log(event).await
    }
}

/// File-based audit logger.
pub struct FileAuditLogger {
    /// File path for audit logs
    file_path: String,
    /// File handle
    file: Arc<Mutex<Option<File>>>,
}

impl FileAuditLogger {
    /// Creates a new file audit logger.
    pub fn new(file_path: String) -> BaffaoResult<Self> {
        // Create or open the file
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .map_err(|e| BaffaoError::Io(format!("Failed to open audit log file: {}", e)))?;
            
        Ok(Self {
            file_path,
            file: Arc::new(Mutex::new(Some(file))),
        })
    }
    
    /// Creates a new file audit logger, creating parent directories if needed.
    pub fn with_dirs(file_path: String) -> BaffaoResult<Self> {
        // Create parent directories if needed
        if let Some(parent) = Path::new(&file_path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BaffaoError::Io(format!("Failed to create audit log directory: {}", e)))?;
        }
        
        Self::new(file_path)
    }
    
    /// Reopens the log file if it was closed.
    async fn reopen_if_needed(&self) -> BaffaoResult<()> {
        let mut file_lock = self.file.lock().await;
        
        if file_lock.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.file_path)
                .map_err(|e| BaffaoError::Io(format!("Failed to reopen audit log file: {}", e)))?;
                
            *file_lock = Some(file);
        }
        
        Ok(())
    }
}

#[async_trait]
impl AuditLogger for FileAuditLogger {
    async fn log(&self, event: AuditEvent) -> BaffaoResult<()> {
        // Reopen the file if needed
        self.reopen_if_needed().await?;
        
        // Serialize the event to JSON
        let event_json = serde_json::to_string(&event)
            .map_err(|e| BaffaoError::Serialization(format!("Failed to serialize audit event: {}", e)))?;
            
        // Write to the file
        let mut file_lock = self.file.lock().await;
        if let Some(file) = &mut *file_lock {
            writeln!(file, "{}", event_json)
                .map_err(|e| BaffaoError::Io(format!("Failed to write audit event: {}", e)))?;
                
            file.flush()
                .map_err(|e| BaffaoError::Io(format!("Failed to flush audit log: {}", e)))?;
        }
        
        Ok(())
    }
}

/// Console audit logger that prints to stdout.
#[derive(Default)]
pub struct ConsoleAuditLogger {}

impl ConsoleAuditLogger {
    /// Creates a new console audit logger.
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl AuditLogger for ConsoleAuditLogger {
    async fn log(&self, event: AuditEvent) -> BaffaoResult<()> {
        // Format the event for display
        let timestamp = event.timestamp.to_rfc3339();
        let level = event.level.to_string();
        let category = &event.category;
        let event_type = &event.event_type;
        let message = &event.message;
        
        // Construct a basic log line
        let log_line = format!("[{}] [{}] [{}:{}] {}", timestamp, level, category, event_type, message);
        println!("{}", log_line);
        
        // Print additional context if available
        if event.user_id.is_some() || event.client_id.is_some() || event.ip_address.is_some() {
            let context = json!({
                "user_id": event.user_id,
                "client_id": event.client_id,
                "ip_address": event.ip_address,
                "session_id": event.session_id,
                "outcome": event.outcome,
                "data": event.data,
            });
            println!("  Context: {}", context);
        }
        
        Ok(())
    }
}