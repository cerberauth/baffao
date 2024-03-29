use crate::settings;
use cookie::Cookie;

pub fn new_cookie(config: settings::CookieConfig, value: String) -> Cookie<'static> {
    Cookie::build((config.name, value))
        .domain(config.domain)
        .path("/")
        .secure(config.secure)
        .http_only(config.http_only)
        .same_site(config.same_site)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings;
    #[test]

    fn test_new_cookie() {
        let config = settings::CookieConfig {
            name: "test_cookie".to_string(),
            domain: "example.com".to_string(),
            secure: true,
            http_only: true,
            same_site: cookie::SameSite::Strict,
        };
        let value = "test_value".to_string();

        let cookie = new_cookie(config, value);

        assert_eq!(cookie.name(), "test_cookie");
        assert_eq!(cookie.value(), "test_value");
        assert_eq!(cookie.domain(), Some("example.com"));
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(cookie::SameSite::Strict));
    }
}
