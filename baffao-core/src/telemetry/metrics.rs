//! Metrics collection and reporting.

use std::sync::{Arc, Mutex, Once};
use std::time::{Duration, Instant};

use prometheus::{
    self, register_counter_vec, register_histogram_vec, register_int_counter,
    register_int_counter_vec, register_int_gauge, CounterVec, HistogramVec,
    IntCounter, IntCounterVec, IntGauge, Opts,
};

use crate::error::{BaffaoError, BaffaoResult};
use super::config::MetricsConfig;
use super::{TokenOperation, AuthOperation};

static INIT: Once = Once::new();
static mut REGISTRY: Option<Arc<MetricsRegistry>> = None;

/// Registry for all metrics collected by Baffao.
#[derive(Clone)]
pub struct MetricsRegistry {
    // Request metrics
    pub http_requests_total: IntCounterVec,
    pub http_request_duration_seconds: HistogramVec,
    pub http_request_size_bytes: HistogramVec,
    pub http_response_size_bytes: HistogramVec,
    
    // Token metrics
    pub token_operations_total: IntCounterVec,
    pub token_operation_duration_seconds: HistogramVec,
    pub tokens_active: IntGauge,
    pub token_errors_total: IntCounterVec,
    
    // Auth metrics
    pub auth_operations_total: IntCounterVec,
    pub auth_operation_duration_seconds: HistogramVec,
    pub auth_errors_total: IntCounterVec,
    
    // Storage metrics
    pub storage_operation_total: IntCounterVec,
    pub storage_operation_duration_seconds: HistogramVec,
    pub storage_errors_total: IntCounterVec,
    
    // Security metrics
    pub rate_limit_exceeded_total: IntCounter,
    pub validation_failures_total: IntCounterVec,
    
    // System metrics
    pub process_start_time_seconds: IntGauge,
    pub process_cpu_seconds_total: IntCounter,
    pub process_resident_memory_bytes: IntGauge,
    pub process_virtual_memory_bytes: IntGauge,
    
    // Collector configuration
    pub config: MetricsConfig,
    pub push_job: Option<Mutex<tokio::task::JoinHandle<()>>>,
}

/// Initialize metrics collection based on configuration.
pub fn setup_metrics(config: &MetricsConfig) -> BaffaoResult<Arc<MetricsRegistry>> {
    unsafe {
        if let Some(registry) = REGISTRY.as_ref() {
            return Ok(registry.clone());
        }
    }
    
    // Only initialize metrics once
    let mut result: BaffaoResult<Arc<MetricsRegistry>> = Err(BaffaoError::Internal(
        "Failed to initialize metrics registry".to_string(),
    ));
    
    INIT.call_once(|| {
        let registry = match create_metrics_registry(config) {
            Ok(registry) => registry,
            Err(e) => {
                result = Err(e);
                return;
            }
        };
        
        // Store registry for future access
        unsafe {
            REGISTRY = Some(registry.clone());
        }
        
        result = Ok(registry);
    });
    
    result
}

/// Get the metrics registry if it has been initialized.
pub fn get_registry() -> Option<Arc<MetricsRegistry>> {
    unsafe { REGISTRY.clone() }
}

/// Record a token operation with metrics.
pub fn record_token_operation(
    operation: TokenOperation, 
    client_id: &str,
    success: bool,
    duration: Option<Duration>,
) {
    if let Some(registry) = get_registry() {
        let result = if success { "success" } else { "failure" };
        
        // Increment the operation counter
        registry.token_operations_total
            .with_label_values(&[operation.as_str(), client_id, result])
            .inc();
            
        // Record operation duration if provided
        if let Some(duration) = duration {
            registry.token_operation_duration_seconds
                .with_label_values(&[operation.as_str(), client_id])
                .observe(duration.as_secs_f64());
        }
        
        // If operation failed, record an error
        if !success {
            registry.token_errors_total
                .with_label_values(&[operation.as_str(), client_id])
                .inc();
        }
        
        // Update active tokens count for issue/revoke operations
        match operation {
            TokenOperation::Issue => {
                if success {
                    registry.tokens_active.inc();
                }
            },
            TokenOperation::Revoke => {
                if success {
                    registry.tokens_active.dec();
                }
            },
            _ => {}
        }
    }
}

/// Record an authentication operation with metrics.
pub fn record_auth_operation(
    operation: AuthOperation,
    client_id: &str,
    success: bool,
    duration: Option<Duration>,
) {
    if let Some(registry) = get_registry() {
        let result = if success { "success" } else { "failure" };
        
        // Increment the operation counter
        registry.auth_operations_total
            .with_label_values(&[operation.as_str(), client_id, result])
            .inc();
            
        // Record operation duration if provided
        if let Some(duration) = duration {
            registry.auth_operation_duration_seconds
                .with_label_values(&[operation.as_str(), client_id])
                .observe(duration.as_secs_f64());
        }
        
        // If operation failed, record an error
        if !success {
            registry.auth_errors_total
                .with_label_values(&[operation.as_str(), client_id])
                .inc();
        }
        
        // For validation failures, record specific metric
        if !success && matches!(
            operation,
            AuthOperation::PkceVerify | AuthOperation::CsrfVerify | AuthOperation::DPoPVerify
        ) {
            registry.validation_failures_total
                .with_label_values(&[operation.as_str(), client_id])
                .inc();
        }
    }
}

/// Create a new metrics registry with all metrics registered.
fn create_metrics_registry(config: &MetricsConfig) -> BaffaoResult<Arc<MetricsRegistry>> {
    // Request metrics
    let http_requests_total = register_int_counter_vec!(
        "baffao_http_requests_total",
        "Total number of HTTP requests",
        &["method", "path", "status"]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let http_request_duration_seconds = register_histogram_vec!(
        "baffao_http_request_duration_seconds",
        "HTTP request duration in seconds",
        &["method", "path"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let http_request_size_bytes = register_histogram_vec!(
        "baffao_http_request_size_bytes",
        "HTTP request size in bytes",
        &["method", "path"],
        vec![100.0, 1000.0, 10000.0, 100000.0, 1000000.0]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let http_response_size_bytes = register_histogram_vec!(
        "baffao_http_response_size_bytes",
        "HTTP response size in bytes",
        &["method", "path", "status"],
        vec![100.0, 1000.0, 10000.0, 100000.0, 1000000.0]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    // Token metrics
    let token_operations_total = register_int_counter_vec!(
        "baffao_token_operations_total",
        "Total number of token operations",
        &["operation", "client_id", "result"]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let token_operation_duration_seconds = register_histogram_vec!(
        "baffao_token_operation_duration_seconds",
        "Token operation duration in seconds",
        &["operation", "client_id"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let tokens_active = register_int_gauge!(
        "baffao_tokens_active",
        "Number of currently active tokens"
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let token_errors_total = register_int_counter_vec!(
        "baffao_token_errors_total",
        "Total number of token errors",
        &["operation", "client_id"]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    // Auth metrics
    let auth_operations_total = register_int_counter_vec!(
        "baffao_auth_operations_total",
        "Total number of authentication operations",
        &["operation", "client_id", "result"]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let auth_operation_duration_seconds = register_histogram_vec!(
        "baffao_auth_operation_duration_seconds",
        "Authentication operation duration in seconds",
        &["operation", "client_id"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let auth_errors_total = register_int_counter_vec!(
        "baffao_auth_errors_total",
        "Total number of authentication errors",
        &["operation", "client_id"]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    // Storage metrics
    let storage_operation_total = register_int_counter_vec!(
        "baffao_storage_operation_total",
        "Total number of storage operations",
        &["operation", "backend", "result"]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let storage_operation_duration_seconds = register_histogram_vec!(
        "baffao_storage_operation_duration_seconds",
        "Storage operation duration in seconds",
        &["operation", "backend"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let storage_errors_total = register_int_counter_vec!(
        "baffao_storage_errors_total",
        "Total number of storage errors",
        &["operation", "backend"]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    // Security metrics
    let rate_limit_exceeded_total = register_int_counter!(
        "baffao_rate_limit_exceeded_total",
        "Total number of rate limit exceeded events"
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let validation_failures_total = register_int_counter_vec!(
        "baffao_validation_failures_total",
        "Total number of validation failures",
        &["validation_type", "client_id"]
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    // System metrics
    let process_start_time_seconds = register_int_gauge!(
        "baffao_process_start_time_seconds",
        "Start time of the process since unix epoch in seconds"
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let process_cpu_seconds_total = register_int_counter!(
        "baffao_process_cpu_seconds_total",
        "Total user and system CPU time spent in seconds"
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let process_resident_memory_bytes = register_int_gauge!(
        "baffao_process_resident_memory_bytes",
        "Resident memory size in bytes"
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    let process_virtual_memory_bytes = register_int_gauge!(
        "baffao_process_virtual_memory_bytes",
        "Virtual memory size in bytes"
    ).map_err(|e| BaffaoError::Internal(format!("Failed to register metric: {}", e)))?;
    
    // Set initial values for system metrics
    let start_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    process_start_time_seconds.set(start_time);
    
    // Create registry
    let registry = Arc::new(MetricsRegistry {
        http_requests_total,
        http_request_duration_seconds,
        http_request_size_bytes,
        http_response_size_bytes,
        token_operations_total,
        token_operation_duration_seconds,
        tokens_active,
        token_errors_total,
        auth_operations_total,
        auth_operation_duration_seconds,
        auth_errors_total,
        storage_operation_total,
        storage_operation_duration_seconds,
        storage_errors_total,
        rate_limit_exceeded_total,
        validation_failures_total,
        process_start_time_seconds,
        process_cpu_seconds_total,
        process_resident_memory_bytes,
        process_virtual_memory_bytes,
        config: config.clone(),
        push_job: None,
    });
    
    // If a push gateway is configured, start a background task to push metrics
    if let Some(push_gateway) = &config.push_gateway {
        if config.enabled {
            let push_gateway = push_gateway.clone();
            let interval_secs = config.push_interval_seconds;
            let registry_clone = registry.clone();
            
            let handle = tokio::spawn(async move {
                let job_name = "baffao";
                let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
                
                loop {
                    interval.tick().await;
                    
                    // Update system metrics before pushing
                    update_system_metrics(&registry_clone);
                    
                    // Push metrics to the gateway
                    if let Err(e) = prometheus::push_metrics(
                        job_name,
                        prometheus::labels! {},
                        &push_gateway,
                        prometheus::default_registry(),
                        prometheus::BasicAuthentication::None,
                    ) {
                        tracing::error!("Failed to push metrics to gateway: {}", e);
                    }
                }
            });
            
            let registry_ptr = Arc::get_mut(&mut (registry.clone()))
                .expect("Failed to get mutable reference to metrics registry");
                
            registry_ptr.push_job = Some(Mutex::new(handle));
        }
    }
    
    Ok(registry)
}

/// Update system metrics with current values.
fn update_system_metrics(registry: &MetricsRegistry) {
    // This is a basic implementation - in a real system you might use crates
    // like sysinfo to get more detailed and accurate system information
    
    // Set CPU time (simplified)
    registry.process_cpu_seconds_total.inc();
    
    // Set memory usage (these are placeholders - real implementation would use system APIs)
    registry.process_resident_memory_bytes.set(
        std::mem::size_of::<MetricsRegistry>() as i64
    );
    registry.process_virtual_memory_bytes.set(
        std::mem::size_of::<MetricsRegistry>() as i64 * 2
    );
}