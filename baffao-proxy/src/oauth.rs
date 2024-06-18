use crate::Settings;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::CookieJar;
use baffao::{
    handlers::{oauth2_authorize, oauth2_callback, AuthorizationCallbackQuery, AuthorizationQuery},
    oauth::OAuthHttpHandler,
};

// TODO: use signed cookies
pub async fn authorize(
    jar: CookieJar,
    query: Option<Query<AuthorizationQuery>>,
    State(handler): State<OAuthHttpHandler>,
) -> impl IntoResponse {
    let (updated_jar, _, url) = oauth2_authorize(handler, jar, query.map(|q| q.0));

    (updated_jar, Redirect::temporary(&url.to_string()))
}

pub async fn callback(
    jar: CookieJar,
    Query(query): Query<AuthorizationCallbackQuery>,
    State(handler): State<OAuthHttpHandler>,
    State(settings): State<Settings>,
) -> impl IntoResponse {
    let (updated_jar, _, url) = oauth2_callback(handler, settings.server, jar, query).await;

    (updated_jar, Redirect::temporary(&url.to_string()))
}

pub async fn introspect(
    jar: CookieJar,
    State(handler): State<OAuthHttpHandler>,
) -> impl IntoResponse {
    handler.introspect(jar).await;
}
