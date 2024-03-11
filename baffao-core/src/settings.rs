use axum_extra::extract::cookie::SameSite;
use reqwest::Url;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub base_url: String,
    pub cookies: CookiesConfig,
}

impl ServerConfig {
    pub fn base_url(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn scheme(&self) -> String {
        Url::parse(&self.base_url).unwrap().scheme().to_string()
    }

    pub fn domain(&self) -> String {
        Url::parse(&self.base_url)
            .unwrap()
            .domain()
            .unwrap()
            .to_string()
    }
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct OAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub metadata_url: Option<String>,
    pub authorization_redirect_uri: String,
    pub authorization_url: String,
    pub token_url: String,
    pub userinfo_url: Option<String>,
    pub redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct JwtConfig {
    pub secret: String,
    pub issuer: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
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

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct CookiesConfig {
    pub csrf: CookieConfig,
    pub access_token: CookieConfig,
    pub refresh_token: CookieConfig,
    pub id_token: CookieConfig,
}
