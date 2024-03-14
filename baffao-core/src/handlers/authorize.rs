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
        oauth_csrf: oauth_csrf_cookie,
        oauth_pkce: oauth_pkce_cookie,
        ..
    }: CookiesConfig,
) -> (CookieJar, StatusCode, String) {
    let scope = query
        .and_then(|q| q.scope)
        .map(|scope| scope.split(' ').map(String::from).collect());
    let (url, csrf_token, pkce_code_verifier) = client.build_authorization_url(scope);

    (
        jar.add(new_cookie(
            oauth_csrf_cookie,
            csrf_token.secret().to_string(),
        ))
        .add(new_cookie(
            oauth_pkce_cookie,
            pkce_code_verifier.secret().to_string(),
        )),
        StatusCode::TEMPORARY_REDIRECT,
        url.to_string(),
    )
}
