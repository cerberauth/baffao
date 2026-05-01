//! Utility functions for the Baffao library.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::BaffaoResult;

/// Generates a cryptographically secure random string.
pub fn generate_secure_random_string(length: usize) -> String {
    let mut buffer = vec![0u8; length];
    OsRng.fill_bytes(&mut buffer);
    URL_SAFE_NO_PAD.encode(buffer)
}

/// Gets the current Unix timestamp.
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Creates a secure cookie name with the __Host- prefix.
pub fn create_secure_cookie_name(name: &str) -> String {
    if name.starts_with("__Host-") {
        name.to_string()
    } else {
        format!("__Host-{}", name)
    }
}

/// Extracts a token from an Authorization header.
pub fn extract_token_from_header(header: Option<&str>) -> Option<String> {
    header.and_then(|h| {
        if h.starts_with("Bearer ") {
            Some(h[7..].to_string())
        } else {
            None
        }
    })
}

/// Extracts a session ID from a cookie.
pub fn extract_session_id_from_cookie(cookie: Option<&str>, cookie_name: &str) -> Option<String> {
    cookie.and_then(|c| {
        c.split(';')
            .map(|kv| kv.trim())
            .filter_map(|kv| {
                let parts: Vec<&str> = kv.splitn(2, '=').collect();
                if parts.len() == 2 && parts[0] == cookie_name {
                    Some(parts[1].to_string())
                } else {
                    None
                }
            })
            .next()
    })
}

/// Returns true if the URL is a relative URL.
pub fn is_relative_url(url: &str) -> bool {
    !url.contains("://") && url.starts_with('/')
}

/// Creates a full URL from a base URL and a path.
pub fn create_full_url(base: &str, path: &str) -> BaffaoResult<url::Url> {
    let mut base_url = url::Url::parse(base)
        .map_err(|_| crate::error::BaffaoError::InvalidUrl(base.to_string()))?;

    if base_url.path().ends_with('/') {
        let path = base_url.path().to_string();
        let path = path.trim_end_matches('/');
        base_url.set_path(path);
    }

    let path = if path.starts_with('/') {
        &path[1..]
    } else {
        path
    };

    base_url
        .join(path)
        .map_err(|_| crate::error::BaffaoError::InvalidUrl(format!("{}/{}", base, path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secure_random_string() {
        let s1 = generate_secure_random_string(32);
        let s2 = generate_secure_random_string(32);

        assert_eq!(s1.len(), 43); // Base64 encoded 32 bytes
        assert_ne!(s1, s2); // Should be different
    }

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        assert!(ts > 0);
    }

    #[test]
    fn test_create_secure_cookie_name() {
        assert_eq!(create_secure_cookie_name("session"), "__Host-session");
        assert_eq!(
            create_secure_cookie_name("__Host-session"),
            "__Host-session"
        );
    }

    #[test]
    fn test_extract_token_from_header() {
        assert_eq!(
            extract_token_from_header(Some("Bearer token123")),
            Some("token123".to_string())
        );
        assert_eq!(extract_token_from_header(Some("token123")), None);
        assert_eq!(extract_token_from_header(None), None);
    }

    #[test]
    fn test_extract_session_id_from_cookie() {
        assert_eq!(
            extract_session_id_from_cookie(Some("session=abc123; Path=/; HttpOnly"), "session"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_session_id_from_cookie(Some("other=xyz; session=abc123; Path=/"), "session"),
            Some("abc123".to_string())
        );
        assert_eq!(
            extract_session_id_from_cookie(Some("other=xyz; Path=/"), "session"),
            None
        );
    }

    #[test]
    fn test_is_relative_url() {
        assert!(is_relative_url("/api/users"));
        assert!(!is_relative_url("https://example.com/api/users"));
        assert!(!is_relative_url("http://example.com"));
    }

    #[test]
    fn test_create_full_url() {
        assert_eq!(
            create_full_url("https://example.com", "/api/users")
                .unwrap()
                .to_string(),
            "https://example.com/api/users"
        );
        assert_eq!(
            create_full_url("https://example.com/", "api/users")
                .unwrap()
                .to_string(),
            "https://example.com/api/users"
        );
    }
}
