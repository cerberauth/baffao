use axum_extra::extract::CookieJar;

use super::Session;
use crate::{cookies::new_cookie, settings::CookieConfig};

pub fn update_session(jar: CookieJar, config: CookieConfig, session: Option<Session>) -> CookieJar {
    let encoded_session = session
        .unwrap_or_else(|| Session::new(None, None, None))
        .encode_cookie();
    jar.add(new_cookie(config, encoded_session))
}
