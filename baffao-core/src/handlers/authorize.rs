use axum_extra::extract::CookieJar;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::{cookies::new_cookie, oauth::OAuthClient, settings::CookiesConfig};

#[derive(Deserialize)]
pub struct AuthorizationQuery {
    pub scope: Option<String>,
}

pub fn oauth2_authorize(
    jar: CookieJar,
    query: Option<AuthorizationQuery>,
    client: OAuthClient,
    CookiesConfig {
        csrf: csrf_cookie, ..
    }: CookiesConfig,
) -> (CookieJar, StatusCode, String) {
    let scopes = query
        .map(|q| q.scope.unwrap_or_default())
        .unwrap_or_default()
        .split_whitespace()
        .map(|s| s.to_string())
        .collect();
    let (url, csrf_token) = client.get_authorization_url(scopes);

    (
        jar.add(new_cookie(csrf_cookie, csrf_token.secret().to_string())),
        StatusCode::TEMPORARY_REDIRECT,
        url.to_string(),
    )
}
