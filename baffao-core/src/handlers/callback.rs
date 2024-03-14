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
        oauth_csrf: oauth_csrf_cookie,
        oauth_pkce: oauth_pkce_cookie,
        access_token: access_token_cookie,
        refresh_token: refresh_token_cookie,
        session: session_cookie,
        ..
    }: CookiesConfig,
) -> Result<(CookieJar, StatusCode, String), Error> {
    let pkce_code = jar
        .get(oauth_csrf_cookie.name.as_str())
        .map(|cookie| cookie.value().to_string());
    if pkce_code.is_none() {
        return Err(anyhow::anyhow!("CSRF token not found"));
    } else if pkce_code.unwrap() != query.state {
        return Err(anyhow::anyhow!("CSRF token mismatch"));
    }

    let pkce_verifier = jar
        .get(oauth_pkce_cookie.name.as_str())
        .map(|cookie| cookie.value().to_string());
    if pkce_verifier.is_none() {
        return Err(anyhow::anyhow!("PKCE verifier not found"));
    }

    if query.code.is_empty() {
        return Err(anyhow::anyhow!("Authorization code not found"));
    }

    let mut updated_jar = jar
        .remove(Cookie::from(oauth_csrf_cookie.name))
        .remove(Cookie::from(oauth_pkce_cookie.name));

    let token_result = match client
        .exchange_code(query.code, pkce_verifier.unwrap())
        .await
    {
        Ok(response) => response,
        Err(_) => {
            return Ok((
                updated_jar,
                StatusCode::INTERNAL_SERVER_ERROR,
                "/error".to_string(),
            ));
        }
    };

    updated_jar = updated_jar.add(new_cookie(
        access_token_cookie,
        token_result.access_token().secret().to_string(),
    ));
    updated_jar = if token_result.refresh_token().is_some() {
        updated_jar.add(new_cookie(
            refresh_token_cookie,
            token_result.refresh_token().unwrap().secret().to_string(),
        ))
    } else {
        updated_jar.remove(Cookie::from(refresh_token_cookie.name))
    };

    let now = Utc::now();
    let expires_in = token_result.expires_in().map(|duration| {
        now.checked_add_signed(Duration::from_std(duration).unwrap())
            .unwrap()
    });
    let session = Session::new(None, Some(now), expires_in);
    updated_jar = update_session(updated_jar, session_cookie, Some(session));

    Ok((updated_jar, StatusCode::TEMPORARY_REDIRECT, "/".to_string()))
}
