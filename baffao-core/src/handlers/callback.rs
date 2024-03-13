use anyhow::Error;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use chrono::{Duration, Utc};
use oauth2::TokenResponse;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::{
    cookies::new_cookie,
    oauth::OAuthClient,
    session::{update_session, Session},
    settings::CookiesConfig,
};

#[derive(Deserialize)]
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
        session: session_cookie,
        ..
    }: CookiesConfig,
) -> Result<(CookieJar, StatusCode, String), Error> {
    let pkce_code = jar
        .get(csrf_cookie.name.as_str())
        .map(|cookie| cookie.value().to_string())
        .unwrap_or_default();
    let response = match client
        .exchange_code(query.code, pkce_code, query.state.clone())
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return Err(e);
        }
    };

    let mut updated_jar = jar.clone();
    updated_jar = updated_jar.remove(Cookie::from(csrf_cookie.name));
    updated_jar = updated_jar.add(new_cookie(
        access_token_cookie,
        response.access_token().secret().to_string(),
    ));
    updated_jar = if response.refresh_token().is_some() {
        updated_jar.add(new_cookie(
            refresh_token_cookie,
            response.refresh_token().unwrap().secret().to_string(),
        ))
    } else {
        updated_jar.remove(Cookie::from(refresh_token_cookie.name))
    };

    let now = Utc::now();
    let expires_in = response.expires_in().map(|duration| {
        now.checked_add_signed(Duration::from_std(duration).unwrap())
            .unwrap()
    });
    let session = Session::new(None, Some(now), expires_in);
    updated_jar = update_session(updated_jar, session_cookie, Some(session));

    Ok((updated_jar, StatusCode::TEMPORARY_REDIRECT, "/".to_string()))
}
