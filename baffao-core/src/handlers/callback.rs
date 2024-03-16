use axum_extra::extract::cookie::{Cookie, CookieJar};
use reqwest::StatusCode;
use serde::Deserialize;

use crate::{
    error::build_error_redirect_url,
    oauth::OAuthHttpHandler,
    settings::{CookiesConfig, ServerConfig},
};

#[derive(Deserialize)]
pub struct AuthorizationCallbackQuery {
    pub code: String,
    pub state: String,
}

pub async fn oauth2_callback(
    handler: OAuthHttpHandler,
    config: ServerConfig,
    jar: CookieJar,
    query: AuthorizationCallbackQuery,
) -> (CookieJar, StatusCode, String) {
    let ServerConfig {
        error_url,
        cookies:
            CookiesConfig {
                oauth_csrf: oauth_csrf_cookie,
                oauth_pkce: oauth_pkce_cookie,
                ..
            },
        ..
    } = config;

    let pkce_code = jar
        .get(oauth_csrf_cookie.name.as_str())
        .map(|cookie| cookie.value().to_string());
    if pkce_code.is_none() {
        return (
            jar,
            StatusCode::TEMPORARY_REDIRECT,
            build_error_redirect_url(&error_url, "CSRF token not found"),
        );
    } else if pkce_code.unwrap() != query.state {
        return (
            jar,
            StatusCode::TEMPORARY_REDIRECT,
            build_error_redirect_url(&error_url, "CSRF token mismatch"),
        );
    }

    let pkce_verifier = jar
        .get(oauth_pkce_cookie.name.as_str())
        .map(|cookie| cookie.value().to_string());
    if pkce_verifier.is_none() {
        return (
            jar,
            StatusCode::TEMPORARY_REDIRECT,
            build_error_redirect_url(&error_url, "PKCE verifier not found"),
        );
    }

    if query.code.is_empty() {
        return (
            jar,
            StatusCode::TEMPORARY_REDIRECT,
            build_error_redirect_url(&error_url, "Authorization code not found"),
        );
    }

    let mut updated_jar = jar
        .remove(Cookie::from(oauth_csrf_cookie.name))
        .remove(Cookie::from(oauth_pkce_cookie.name));

    updated_jar = match handler
        .exchange_code(updated_jar.to_owned(), query.code, pkce_verifier.unwrap())
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return (
                updated_jar,
                StatusCode::TEMPORARY_REDIRECT,
                build_error_redirect_url(&error_url, &e.to_string()),
            );
        }
    };

    (updated_jar, StatusCode::TEMPORARY_REDIRECT, "/".to_string())
}
