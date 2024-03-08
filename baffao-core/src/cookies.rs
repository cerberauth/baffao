use cookie::Cookie;
use crate::settings;

pub fn new_cookie(
    config: settings::CookieConfig,
    value: String,
) -> Cookie<'static> {
    Cookie::build((config.name, value))
        .domain(config.domain)
        .path("/")
        .secure(config.secure)
        .http_only(config.http_only)
        .same_site(config.same_site)
        .build()
}
