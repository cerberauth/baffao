use anyhow::{Error, Ok};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{cookies::new_cookie, oauth::client::OAuthClient, settings::CookiesConfig};

#[derive(Debug, Deserialize)]
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
) -> Result<(CookieJar, String), Error> {
    let (url, csrf_token) = client.get_authorization_url(
        query
            .map(|q| q.scope.unwrap_or_default())
            .unwrap_or_default()
            .split_whitespace()
            .map(|s| s.to_string())
            .collect(),
    );

    Ok((
        jar.add(new_cookie(csrf_cookie, csrf_token.secret().to_string())),
        url.to_string(),
    ))
}
