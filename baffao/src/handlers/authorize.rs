use axum_extra::extract::CookieJar;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::openidconnect::OAuthHttpHandler;

#[derive(Deserialize)]
pub struct AuthorizationQuery {
    pub scope: Option<String>,
}

pub fn oauth2_authorize(
    handler: OAuthHttpHandler,
    jar: CookieJar,
    query: Option<AuthorizationQuery>,
) -> (CookieJar, StatusCode, String) {
    let scope = query
        .and_then(|q| q.scope)
        .map(|scope| scope.split(' ').map(String::from).collect());
    let (updated_jar, url) = handler.authorize(jar, scope);

    (updated_jar, StatusCode::TEMPORARY_REDIRECT, url.to_string())
}
