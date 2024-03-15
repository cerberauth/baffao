use crate::Settings;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::CookieJar;
use baffao_core::{
    handlers::{oauth2_authorize, oauth2_callback, AuthorizationCallbackQuery, AuthorizationQuery},
    oauth::OAuthClient,
};

// TODO: use signed cookies
pub async fn authorize(
    jar: CookieJar,
    query: Option<Query<AuthorizationQuery>>,
    State(client): State<OAuthClient>,
    State(settings): State<Settings>,
) -> impl IntoResponse {
    let (updated_jar, _, url) = oauth2_authorize(client, settings.server, jar, query.map(|q| q.0));

    (updated_jar, Redirect::temporary(&url.to_string()))
}

pub async fn callback(
    jar: CookieJar,
    Query(query): Query<AuthorizationCallbackQuery>,
    State(client): State<OAuthClient>,
    State(settings): State<Settings>,
) -> impl IntoResponse {
    let (updated_jar, _, url) = oauth2_callback(client, settings.server, jar, query).await;

    (updated_jar, Redirect::temporary(&url.to_string()))
}
