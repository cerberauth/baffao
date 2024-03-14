use axum::{extract::State, response::IntoResponse, Json};
use axum_extra::extract::cookie::CookieJar;
use baffao_core::{handlers::get_session_from_cookie, session::Session};
use serde::Serialize;

use crate::settings::Settings;

#[derive(Serialize)]
struct SessionResponse {
    session: Option<Session>,
}

pub async fn get_session(jar: CookieJar, State(settings): State<Settings>) -> impl IntoResponse {
    let (updated_jar, session) = get_session_from_cookie(jar, settings.server.cookies);

    (updated_jar, Json(SessionResponse { session }))
}
