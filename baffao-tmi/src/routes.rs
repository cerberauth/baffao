use std::sync::Arc;

use axum::{
    extract::State,
    http::Method,
    routing::{get, post},
    Router,
};
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, services::ServeDir, trace::TraceLayer,
};

use baffao_core::session::SessionManager;
use baffao_core::token::TokenManager;

use crate::handlers;
use crate::middleware::csrf::CsrfProtection;
use crate::state::TmiState;

/// Creates the router for the TMI
pub fn create_router<S, T>(state: TmiState<S, T>) -> Router
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    let state = Arc::new(state);

    // Create base middleware stack
    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new());

    // Add CORS if configured
    let middleware = if let Some(origin) = &state.config.cors_origin {
        middleware.layer(
            CorsLayer::new()
                .allow_origin(origin.parse::<http::HeaderValue>().unwrap())
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_credentials(true)
                .allow_headers([
                    http::header::CONTENT_TYPE,
                    http::header::AUTHORIZATION,
                    http::header::ACCEPT,
                    http::header::ORIGIN,
                    http::header::COOKIE,
                    http::header::HeaderName::from_static("x-csrf-token"),
                ]),
        )
    } else {
        middleware
    };

    // Define the auth routes
    let auth_routes = Router::new()
        .route("/check", get(handlers::auth::check_session::<S, T>))
        .route("/login", get(handlers::auth::login::<S, T>))
        .route("/callback", get(handlers::auth::callback::<S, T>))
        .route("/logout", get(handlers::auth::logout::<S, T>))
        .route(
            "/token",
            post(handlers::auth::get_token::<S, T>)
                .layer(CsrfProtection::new(Arc::clone(&state.csrf_manager))),
        )
        .route(
            "/csrf-token",
            get(handlers::csrf::generate_csrf_token::<S, T>),
        )
        .with_state(Arc::clone(&state));

    // Combine the routes
    let mut router = Router::new()
        .nest(&format!("{}/auth", state.config.base_path), auth_routes)
        .layer(middleware);

    // Add static file serving if configured
    if let Some(path) = &state.config.static_file_path {
        router = router.fallback_service(ServeDir::new(path));
    }

    router
}
