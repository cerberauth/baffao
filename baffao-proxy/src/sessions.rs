use axum::{
    http::{Method, StatusCode},
    response::IntoResponse,
    Json,
};
use axum_extra::extract::cookie::CookieJar;
use baffao_core::{
    cookies::Cookies,
    session::Session,
};
use serde::Serialize;

#[derive(Serialize)]
struct SessionsResponse {
    sessions: Vec<Session>,
}

pub async fn get_sessions(method: Method, jar: Option<CookieJar>) -> impl IntoResponse {
    let jar = jar.unwrap_or_default();
    let cookies = Cookies::new(jar);

    let sessions = cookies.extract_sessions(b"secret");

    if method == Method::HEAD {
        if sessions.is_empty() {
            return (StatusCode::NO_CONTENT, Json(SessionsResponse { sessions: vec![] }));
        }

        // return StatusCode::NO_CONTENT;
        // TODO: make quick check instead on parsing the cookies
    }

    (StatusCode::OK, Json(SessionsResponse { sessions }))
}
