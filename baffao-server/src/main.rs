use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use clap::Parser;
use baffao_core::csrf::CsrfManager;
use baffao_core::session::InMemorySessionManager;
use baffao_core::token::InMemoryTokenManager;
use baffao_backend::{BackendBuilder, BackendConfig, BackendType};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod config;
mod cli;

use config::ServerConfig;
use cli::Cli;

#[tokio::main]
async fn main() {
    // Parse command line arguments
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.log_level.as_deref() {
        Some("debug") => Level::DEBUG,
        Some("trace") => Level::TRACE,
        Some("info") => Level::INFO,
        Some("warn") => Level::WARN,
        Some("error") => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("Failed to set global subscriber");

    // Load configuration
    let config = ServerConfig::from_file(cli.config_file.as_deref())
        .expect("Failed to load configuration");

    // Create the CSRF manager
    let csrf_manager = Arc::new(CsrfManager::new_with_random_secret());

    // Create the session and token managers
    let session_manager = InMemorySessionManager::new();
    let token_manager = InMemoryTokenManager::new();

    // Determine the backend type
    let backend_type = match config.server_type.as_str() {
        "bff" => {
            info!("Starting Baffao in BFF mode");
            BackendType::BFF
        },
        "tmi" => {
            info!("Starting Baffao in TMI mode");
            BackendType::TMI
        },
        _ => {
            panic!("Invalid server type. Must be 'bff' or 'tmi'");
        }
    };

    // Create the unified backend config
    let backend_config = BackendConfig {
        backend_type,
        client_id: config.client_id.clone(),
        client_secret: config.client_secret.clone(),
        auth_url: config.auth_url.clone(),
        token_url: config.token_url.clone(),
        redirect_url: config.redirect_url.clone(),
        default_scopes: config.default_scopes.clone(),
        session_cookie_name: config.session_cookie_name.clone(),
        session_cookie_domain: config.session_cookie_domain.clone(),
        session_cookie_path: config.session_cookie_path.clone(),
        session_cookie_secure: config.session_cookie_secure,
        session_cookie_http_only: config.session_cookie_http_only,
        session_cookie_same_site: config.get_same_site(),
        session_max_age: config.session_max_age,
        state_expiry_seconds: 600, // 10 minutes
        base_path: config.base_path.clone(),
        allowed_proxy_destinations: config.allowed_proxy_destinations.clone(),
        static_file_path: config.static_file_path.clone(),
        cors_origin: config.cors_origin.clone(),
        access_token_lifetime: Some(config.access_token_lifetime),
        issuer: None,
        jwks_uri: None,
    };

    // Build the backend state
    let backend_state = BackendBuilder::new(backend_config)
        .with_session_manager(session_manager)
        .with_token_manager(token_manager)
        .with_csrf_manager(csrf_manager)
        .build()
        .expect("Failed to build backend state");

    // Create the router using the unified API
    let app = baffao_backend::create_router(backend_state);

    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!("Starting Baffao server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("Failed to bind to address");
    axum::serve(listener, app.into_make_service())
        .await
        .expect("Failed to start server");
}