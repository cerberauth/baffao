use axum::{body::Body, extract::FromRef};
use baffao::oauth::OAuthHttpHandler;
use hyper_util::client::legacy::connect::HttpConnector;

use crate::settings::Settings;

pub type HttpClient = hyper_util::client::legacy::Client<HttpConnector, Body>;

#[derive(Clone)]
pub struct AppState {
    pub client: HttpClient,
    pub oauth_http_handler: OAuthHttpHandler,
    pub settings: Settings,
}

impl FromRef<AppState> for OAuthHttpHandler {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_http_handler.clone()
    }
}

impl FromRef<AppState> for Settings {
    fn from_ref(state: &AppState) -> Self {
        state.settings.clone()
    }
}

impl FromRef<AppState> for HttpClient {
    fn from_ref(state: &AppState) -> Self {
        state.client.clone()
    }
}
