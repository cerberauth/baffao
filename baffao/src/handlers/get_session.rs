use axum_extra::extract::CookieJar;

use crate::{
    session::{extract_session, Session},
    settings::CookiesConfig,
};

pub fn get_session_from_cookie(
    jar: CookieJar,
    CookiesConfig {
        session: session_cookie_config,
        ..
    }: CookiesConfig,
) -> (CookieJar, Option<Session>) {
    let session = match extract_session(&jar, &session_cookie_config) {
        Ok(session) => session,
        Err(_) => return (jar.remove(session_cookie_config.name), None),
    };
    if session.is_some() && session.as_ref().unwrap().is_expired() {
        return (jar.remove(session_cookie_config.name), None);
    }

    (jar, session)
}
