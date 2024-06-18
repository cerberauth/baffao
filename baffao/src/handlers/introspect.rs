use axum_extra::extract::CookieJar;
use reqwest::StatusCode;

use crate::oauth::{IntrospectionTokenResponse, OAuthHttpHandler};

pub async fn oauth2_introspect(
    handler: OAuthHttpHandler,
    jar: CookieJar,
) -> (CookieJar, StatusCode, Option<IntrospectionTokenResponse>) {
    let (updated_jar, response) = handler.introspect(jar).await;

    (updated_jar, response.to_owned().map_or_else(|| StatusCode::UNAUTHORIZED, |_| StatusCode::OK), response)
}
