//! Telemetry configuration structures.

use serde::{Deserialize, Serialize};

/// Main configuration for all telemetry components.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsConfig,

    /// Distributed tracing configuration
    #[serde(default)]
    pub tracing: TracingConfig,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            logging: LoggingConfig::default(),
            metrics: MetricsConfig::default(),
            tracing: TracingConfig::default(),
        }
    }
}

/// Configuration for structured logging.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Use JSON formatting for logs
    #[serde(default = "default_json_logs")]
    pub json: bool,

    /// Log file path (if None, logs to stdout)
    #[serde(default)]
    pub file: Option<String>,

    /// Additional fields to include with every log
    #[serde(default)]
    pub fields: std::collections::HashMap<String, String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_json_logs() -> bool {
    false
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            json: default_json_logs(),
            file: None,
            fields: std::collections::HashMap::new(),
        }
    }
}

/// Configuration for metrics collection.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Endpoint for exposing Prometheus metrics
    #[serde(default = "default_prometheus_endpoint")]
    pub prometheus_endpoint: String,

    /// Push gateway URL for Prometheus (if any)
    #[serde(default)]
    pub push_gateway: Option<String>,

    /// Push interval in seconds (if push gateway is configured)
    #[serde(default = "default_push_interval")]
    pub push_interval_seconds: u64,
}

fn default_enabled() -> bool {
    true
}

fn default_prometheus_endpoint() -> String {
    "/metrics".to_string()
}

fn default_push_interval() -> u64 {
    60
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            prometheus_endpoint: default_prometheus_endpoint(),
            push_gateway: None,
            push_interval_seconds: default_push_interval(),
        }
    }
}

/// Configuration for distributed tracing.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TracingConfig {
    /// Enable distributed tracing
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// OpenTelemetry collector endpoint
    #[serde(default)]
    pub collector_endpoint: Option<String>,

    /// Service name to use in traces
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Sampling rate (0.0 - 1.0)
    #[serde(default = "default_sampling_rate")]
    pub sampling_rate: f64,
}

fn default_service_name() -> String {
    "baffao".to_string()
}

fn default_sampling_rate() -> f64 {
    0.1
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            collector_endpoint: None,
            service_name: default_service_name(),
            sampling_rate: default_sampling_rate(),
        }
    }
}
