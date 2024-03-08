use anyhow::{Error, Ok};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{cookies::new_cookie, oauth::client::OAuthClient, settings::CookiesConfig};

#[derive(Debug, Deserialize, Default)]
pub struct AuthorizationCallbackQuery {
    pub code: String,
    pub state: String,
}

pub async fn oauth2_callback(
    jar: CookieJar,
    query: AuthorizationCallbackQuery,
    client: OAuthClient,
    CookiesConfig {
        csrf: csrf_cookie,
        access_token: access_token_cookie,
        refresh_token: refresh_token_cookie,
        ..
    }: CookiesConfig,
) -> Result<(CookieJar, String), Error> {
    let pkce_code = jar
        .get(csrf_cookie.name.as_str())
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default();
    let (access_token, refresh_token, _expires) = client
        .exchange_code(query.code, pkce_code, query.state.clone())
        .await
        .unwrap();

    let mut new_jar = jar.remove(csrf_cookie.name).add(new_cookie(
        access_token_cookie,
        access_token.secret().to_string(),
    ));
    if let Some(refresh_token) = refresh_token {
        new_jar = new_jar.add(new_cookie(
            refresh_token_cookie,
            refresh_token.secret().to_string(),
        ));
    }

    Ok((new_jar, "/".to_string()))
}
