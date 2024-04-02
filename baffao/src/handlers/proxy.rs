use anyhow::{Error, Ok};
use axum_extra::extract::CookieJar;
use http::HeaderMap;

use crate::openidconnect::OAuthHttpHandler;

pub async fn proxy(
    handler: OAuthHttpHandler,
    jar: CookieJar,
) -> Result<(CookieJar, HeaderMap), Error> {
    let (updated_jar, access_token) = handler.get_or_refresh_token(jar).await?;
    if access_token.is_none() {
        return Ok((updated_jar, HeaderMap::new()));
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        "Authorization",
        format!("Bearer {}", access_token.unwrap()).parse()?,
    );

    Ok((updated_jar, headers))
}
