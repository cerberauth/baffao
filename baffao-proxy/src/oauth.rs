use crate::Settings;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::CookieJar;
use baffao_core::oauth::{
    authorize::{oauth2_authorize, AuthorizationQuery},
    callback::{oauth2_callback, AuthorizationCallbackQuery},
    client::OAuthClient,
};

// TODO: use signed cookies
pub async fn authorize(
    request_jar: CookieJar,
    query: Option<Query<AuthorizationQuery>>,
    State(client): State<OAuthClient>,
    State(settings): State<Settings>,
) -> impl IntoResponse {
    let (jar, url) = oauth2_authorize(
        request_jar,
        query.map(|q| q.0),
        client,
        settings.server.cookies.clone(),
    )
    .unwrap();

    (jar, Redirect::temporary(&url.to_string()))
}

pub async fn callback(
    request_jar: CookieJar,
    Query(query): Query<AuthorizationCallbackQuery>,
    State(client): State<OAuthClient>,
    State(settings): State<Settings>,
) -> impl IntoResponse {
    let (jar, url) = oauth2_callback(request_jar, query, client, settings.server.cookies.clone())
        .await
        .unwrap();

    (jar, Redirect::temporary(&url.to_string()))
}
