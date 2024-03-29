use anyhow::{Error, Ok};
use axum_extra::extract::CookieJar;

use super::Session;
use crate::settings::CookieConfig;

pub fn extract_session(jar: &CookieJar, config: &CookieConfig) -> Result<Option<Session>, Error> {
    let encoded_session = jar
        .get(&config.name)
        .map(|cookie| cookie.value().to_string());
    if encoded_session.is_none() {
        return Ok(None);
    }

    let session = Session::decode_cookie(encoded_session.unwrap())?;
    Ok(Some(session))
}

#[cfg(test)]
mod tests {
    use axum_extra::extract::CookieJar;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use cookie::Cookie;

    use super::*;
    use crate::settings::CookieConfig;

    #[test]
    fn test_extract_session() {
        let mut jar = CookieJar::new();
        let config = CookieConfig {
            domain: "localhost".to_string(),
            name: "session".to_string(),
            secure: false,
            http_only: false,
            same_site: cookie::SameSite::Strict,
        };

        let session = Session::new(None, None, None);
        let session_str = serde_json::to_string(&session).unwrap();
        let encoded_cookie = STANDARD.encode(session_str.as_bytes());

        jar = jar.add(Cookie::new(config.name.clone(), encoded_cookie));

        // Extract the session
        let result = extract_session(&jar, &config);

        // Check that the session was extracted correctly
        assert!(result.is_ok());
        let extracted_session = result.unwrap();
        assert!(extracted_session.is_some());
        assert_eq!(extracted_session.unwrap().id, session.id);
    }
}
