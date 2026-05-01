//! Distributed tracing implementation using OpenTelemetry.

use std::sync::Once;
use std::time::{Duration, Instant};

use opentelemetry::{
    global,
    runtime::TokioCurrentThread,
    trace::{TraceContextExt, Tracer, TracerProvider},
    Context, KeyValue,
};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    trace::{self, BatchConfig, IdGenerator, Sampler},
    Resource,
};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, Registry};

use super::config::TracingConfig;
use crate::error::{BaffaoError, BaffaoResult};

static INIT: Once = Once::new();

/// Initialize distributed tracing based on configuration.
pub fn setup_tracing(config: &TracingConfig) -> BaffaoResult<()> {
    if !config.enabled {
        return Ok(());
    }

    // Only initialize tracing once
    let mut result = Ok(());
    INIT.call_once(|| {
        result = match setup_tracing_internal(config) {
            Ok(_) => {
                tracing::info!("Distributed tracing initialized");
                Ok(())
            }
            Err(e) => Err(e),
        };
    });

    result
}

fn setup_tracing_internal(config: &TracingConfig) -> BaffaoResult<()> {
    // Set up the OTLP exporter
    let tracer =
        if let Some(endpoint) = &config.collector_endpoint {
            let otlp_exporter = opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(endpoint);

            // Configure the batch processor
            let batch_config = BatchConfig::default()
                .with_max_queue_size(4096)
                .with_max_export_batch_size(512)
                .with_scheduled_delay(Duration::from_secs(5))
                .with_max_export_timeout(Duration::from_secs(30));

            // Create a sampling config based on the rate
            let sampler = if config.sampling_rate >= 1.0 {
                Sampler::AlwaysOn
            } else if config.sampling_rate <= 0.0 {
                Sampler::AlwaysOff
            } else {
                Sampler::TraceIdRatioBased(config.sampling_rate)
            };

            // Build tracer provider
            opentelemetry_otlp::new_pipeline()
                .tracing()
                .with_exporter(otlp_exporter)
                .with_trace_config(
                    trace::config()
                        .with_sampler(sampler)
                        .with_id_generator(IdGenerator::default())
                        .with_resource(Resource::new(vec![
                            KeyValue::new("service.name", config.service_name.clone()),
                            KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                            KeyValue::new(
                                "deployment.environment",
                                std::env::var("BAFFAO_ENV")
                                    .unwrap_or_else(|_| "development".to_string()),
                            ),
                        ]))
                        .with_batch_config(batch_config),
                )
                .install_batch(TokioCurrentThread)
                .map_err(|e| BaffaoError::Internal(format!("Failed to install tracer: {}", e)))?
        } else {
            // No collector endpoint, use a simple stdout exporter for development
            opentelemetry_stdout::new_pipeline()
                .with_trace_config(trace::config().with_resource(Resource::new(vec![
                    KeyValue::new("service.name", config.service_name.clone()),
                ])))
                .install_simple()
                .map_err(|e| BaffaoError::Internal(format!("Failed to install tracer: {}", e)))?
        };

    // Create an OpenTelemetry layer
    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    // Add the layer to the existing subscriber
    let subscriber = tracing::subscriber::current().with(telemetry);

    // Set as global subscriber
    tracing::subscriber::set_global_default(subscriber).map_err(|e| {
        BaffaoError::Internal(format!("Failed to set global tracing subscriber: {}", e))
    })?;

    // Set up a hook to ensure spans are flushed on process exit
    std::panic::set_hook(Box::new(|panic_info| {
        if let Some(location) = panic_info.location() {
            tracing::error!(
                panic.file = location.file(),
                panic.line = location.line(),
                panic.column = location.column(),
                panic.message = %panic_info,
                "Process panicked"
            );
        } else {
            tracing::error!(
                panic.message = %panic_info,
                "Process panicked at unknown location"
            );
        }

        // Flush tracing spans
        global::shutdown_tracer_provider();
    }));

    Ok(())
}

/// Create a span for tracing HTTP requests.
pub fn trace_request<F, R>(method: &str, path: &str, client_id: Option<&str>, f: F) -> R
where
    F: FnOnce() -> R,
{
    let span = tracing::info_span!(
        "http_request",
        method = method,
        path = path,
        client_id = client_id.unwrap_or("unknown"),
        trace_id = tracing::field::Empty,
    );

    let _guard = span.enter();

    // If OpenTelemetry is available, set the trace ID
    let context = Context::current();
    let span_context = context.span().span_context();
    if span_context.is_valid() {
        let trace_id = format!("{:x}", span_context.trace_id());
        span.record("trace_id", &trace_id);
    }

    // Record timing
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();

    // Record duration in metrics if enabled
    if let Some(registry) = super::metrics::get_registry() {
        registry
            .http_request_duration_seconds
            .with_label_values(&[method, path])
            .observe(duration.as_secs_f64());
    }

    result
}

/// Create a span for tracing token flows.
pub fn trace_token_flow<F, R>(operation: &str, client_id: &str, token_id: Option<&str>, f: F) -> R
where
    F: FnOnce() -> R,
{
    let span = tracing::info_span!(
        "token_flow",
        operation = operation,
        client_id = client_id,
        token_id = token_id.unwrap_or("unknown"),
        trace_id = tracing::field::Empty,
    );

    let _guard = span.enter();

    // If OpenTelemetry is available, set the trace ID
    let context = Context::current();
    let span_context = context.span().span_context();
    if span_context.is_valid() {
        let trace_id = format!("{:x}", span_context.trace_id());
        span.record("trace_id", &trace_id);
    }

    // Record timing
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();

    // Convert operation to token operation for metrics
    let token_op = match operation {
        "issue" => Some(super::metrics::TokenOperation::Issue),
        "refresh" => Some(super::metrics::TokenOperation::Refresh),
        "validate" => Some(super::metrics::TokenOperation::Validate),
        "revoke" => Some(super::metrics::TokenOperation::Revoke),
        _ => None,
    };

    // Record metrics if possible
    if let Some(op) = token_op {
        super::metrics::record_token_operation(
            op,
            client_id,
            true, // Assume success for simplicity
            Some(duration),
        );
    }

    result
}
