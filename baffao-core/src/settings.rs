use axum_extra::extract::cookie::SameSite;
use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub base_url: String,
    pub cookies: CookiesConfig,
    pub error_url: String,
}

#[derive(Deserialize, Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: String,
}

#[derive(Deserialize, Clone)]
pub struct CookieConfig {
    pub name: String,
    pub domain: String,
    pub secure: bool,
    pub http_only: bool,
    #[serde(deserialize_with = "deserialize_same_site")]
    pub same_site: SameSite,
}

fn deserialize_same_site<'de, D>(deserializer: D) -> Result<SameSite, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    match s.to_lowercase().as_str() {
        "lax" => Ok(SameSite::Lax),
        "strict" => Ok(SameSite::Strict),
        "none" => Ok(SameSite::None),
        _ => Err(serde::de::Error::custom("invalid value for SameSite")),
    }
}

impl CookieConfig {
    pub fn to_string_with_value(&self, value: String) -> String {
        let mut cookie = format!(
            "{}={}; Domain={}; Path=/; SameSite={}",
            self.name, value, self.domain, self.same_site
        );

        if self.secure {
            cookie = format!("{}; Secure", cookie)
        }

        if self.http_only {
            cookie = format!("{}; HttpOnly", cookie)
        }

        cookie
    }
}

#[derive(Deserialize, Clone)]
pub struct CookiesConfig {
    pub oauth_csrf: CookieConfig,
    pub oauth_pkce: CookieConfig,
    pub access_token: CookieConfig,
    pub refresh_token: CookieConfig,
    pub session: CookieConfig,
}
