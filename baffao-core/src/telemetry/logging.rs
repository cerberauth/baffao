//! Structured logging implementation.

use std::str::FromStr;
use std::sync::Once;

use tracing::{info, Level};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{
    fmt, fmt::format::JsonFields, fmt::time::UtcTime, layer::SubscriberExt, registry, EnvFilter,
    Layer,
};

use super::config::LoggingConfig;
use crate::error::{BaffaoError, BaffaoResult};

static INIT: Once = Once::new();
static mut WORKER_GUARD: Option<WorkerGuard> = None;

/// Initialize structured logging based on configuration.
pub fn setup_logging(config: &LoggingConfig) -> BaffaoResult<()> {
    // Only initialize logging once
    let mut result = Ok(());
    INIT.call_once(|| {
        result = match setup_logging_internal(config) {
            Ok(_) => {
                info!("Logging initialized with level {}", config.level);
                Ok(())
            }
            Err(e) => Err(e),
        }
    });
    result
}

fn setup_logging_internal(config: &LoggingConfig) -> BaffaoResult<()> {
    // Parse log level
    let log_level = Level::from_str(&config.level)
        .map_err(|_| BaffaoError::Configuration(format!("Invalid log level: {}", config.level)))?;

    // Create filter
    let filter = EnvFilter::from_default_env().add_directive(log_level.into());

    // Determine log destination
    let (non_blocking, guard) = if let Some(file_path) = &config.file {
        let file_appender = tracing_appender::rolling::daily(
            std::path::Path::new(file_path)
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            std::path::Path::new(file_path)
                .file_name()
                .unwrap_or_default(),
        );
        tracing_appender::non_blocking(file_appender)
    } else {
        tracing_appender::non_blocking(std::io::stdout())
    };

    // Store worker guard to ensure logs are flushed on shutdown
    unsafe {
        WORKER_GUARD = Some(guard);
    }

    // Set up subscriber with appropriate formatter
    if config.json {
        // JSON formatter with UTC timestamp
        let json_layer = fmt::layer()
            .json()
            .with_timer(UtcTime::rfc_3339())
            .with_writer(non_blocking);

        // Build and install the subscriber
        let subscriber = registry().with(filter).with(json_layer);

        tracing::subscriber::set_global_default(subscriber).map_err(|e| {
            BaffaoError::Internal(format!("Failed to set global tracing subscriber: {}", e))
        })?;
    } else {
        // Regular formatter with UTC timestamp
        let fmt_layer = fmt::layer()
            .with_timer(UtcTime::rfc_3339())
            .with_writer(non_blocking);

        // Build and install the subscriber
        let subscriber = registry().with(filter).with(fmt_layer);

        tracing::subscriber::set_global_default(subscriber).map_err(|e| {
            BaffaoError::Internal(format!("Failed to set global tracing subscriber: {}", e))
        })?;
    }

    // Install panic hook that logs panic information
    std::panic::set_hook(Box::new(|panic_info| {
        let backtrace = std::backtrace::Backtrace::capture();

        if let Some(location) = panic_info.location() {
            tracing::error!(
                panic.file = location.file(),
                panic.line = location.line(),
                panic.column = location.column(),
                panic.message = panic_info.to_string(),
                "Process panicked"
            );
        } else {
            tracing::error!(
                panic.message = panic_info.to_string(),
                "Process panicked at unknown location"
            );
        }

        tracing::error!(backtrace = ?backtrace, "Backtrace");
    }));

    Ok(())
}
