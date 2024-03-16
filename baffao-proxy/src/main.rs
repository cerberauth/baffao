mod oauth;
mod proxy;
mod session;
mod settings;
mod state;

use axum::{error_handling::HandleErrorLayer, http::StatusCode, routing::{any, get}, Router};
use baffao_core::oauth::OAuthHttpHandler;
use hyper_util::{client::legacy::connect::HttpConnector, rt::TokioExecutor};
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
                .unwrap_or_else(|_| "baffao=trace,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let client: state::HttpClient =
        hyper_util::client::legacy::Client::<(), ()>::builder(TokioExecutor::new())
            .build(HttpConnector::new());
    let oauth_http_handler = OAuthHttpHandler::new(
        settings.oauth.clone(),
        settings.server.cookies.clone(),
    ).unwrap();
    let app_state = state::AppState {
        client,
        oauth_http_handler,
        settings: settings.clone(),
    };

    let app = Router::new()
        .route("/oauth/authorize", get(oauth::authorize))
        .route("/oauth/callback", get(oauth::callback))
        .route("/session", get(session::get_session))
        .fallback(any(proxy::handler))
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
