// mod sessions;
mod oauth;
mod settings;

use axum::{
    error_handling::HandleErrorLayer, extract::FromRef, http::StatusCode, routing::get, Router,
};
use baffao_core::oauth::client::OAuthClient;
use std::time::Duration;
use tokio::signal;
use tower::{timeout::TimeoutLayer, BoxError, ServiceBuilder};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::settings::Settings;

#[tokio::main]
async fn main() {
    let settings = Settings::new().unwrap();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "baffao=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let oauth_client = OAuthClient::new(settings.oauth.clone());

    let app_state = AppState {
        oauth_client,
        settings: settings.clone(),
    };

    let app = Router::new()
        // .route("/sessions", get(sessions::get_sessions))
        .route("/oauth/authorize", get(oauth::authorize))
        .route("/oauth/callback", get(oauth::callback))
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|error: BoxError| async move {
                    if error.is::<tower::timeout::error::Elapsed>() {
                        Ok(StatusCode::REQUEST_TIMEOUT)
                    } else {
                        Err((
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Unhandled internal error: {error}"),
                        ))
                    }
                }))
                .layer((
                    TraceLayer::new_for_http(),
                    TimeoutLayer::new(Duration::from_secs(10)),
                ))
                .into_inner(),
        )
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(
        settings.server.host + ":" + &settings.server.port.to_string(),
    )
    .await
    .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[derive(Clone)]
struct AppState {
    oauth_client: OAuthClient,
    settings: Settings,
}

impl FromRef<AppState> for OAuthClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_client.clone()
    }
}

impl FromRef<AppState> for Settings {
    fn from_ref(state: &AppState) -> Self {
        state.settings.clone()
    }
}
