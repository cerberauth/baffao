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

use crate::config::BackendType;
use crate::handlers;
use crate::middleware::csrf::CsrfProtection;
use crate::state::BackendState;

/// Creates the router for the Backend instance
pub fn create_router<S, T>(state: BackendState<S, T>) -> Router
where
    S: SessionManager + 'static,
    T: TokenManager + 'static,
{
    let state = Arc::new(state);

    // Create base middleware stack
    let middleware = ServiceBuilder::new()
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new());

    // Define the auth routes (common to both modes)
    let mut auth_routes = Router::new()
        .route("/check", get(handlers::check_session::<S, T>))
        .route("/login", get(handlers::login::<S, T>))
        .route("/callback", get(handlers::callback::<S, T>))
        .route("/logout", get(handlers::logout::<S, T>))
        .route("/csrf-token", get(handlers::generate_csrf_token::<S, T>));

    // Add TMI-specific routes
    if state.config.backend_type == BackendType::TMI {
        auth_routes = auth_routes.route(
            "/token",
            post(handlers::get_token::<S, T>)
                .layer(CsrfProtection::new(Arc::clone(&state.csrf_manager))),
        );
    }

    // Define the main router
    let mut router = Router::new().nest(&format!("{}/auth", state.config.base_path), auth_routes);

    // Add BFF-specific routes
    if state.config.backend_type == BackendType::BFF {
        let api_routes = Router::new()
            .route(
                "/api/*path",
                get(handlers::bff::proxy::<S, T>)
                    .post(handlers::bff::proxy::<S, T>)
                    .put(handlers::bff::proxy::<S, T>)
                    .delete(handlers::bff::proxy::<S, T>)
                    .patch(handlers::bff::proxy::<S, T>),
            )
            .layer(CsrfProtection::new(Arc::clone(&state.csrf_manager)));

        router = router.nest(&state.config.base_path, api_routes);
    }

    // Apply state
    let mut router = router.with_state(Arc::clone(&state));

    // Apply middleware
    router = router.layer(middleware);

    // Add CORS if configured
    if let Some(origin) = &state.config.cors_origin {
        router = router.layer(
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
        );
    }

    // Add static file serving if configured
    if let Some(path) = &state.config.static_file_path {
        router = router.fallback_service(ServeDir::new(path));
    }

    router
}
