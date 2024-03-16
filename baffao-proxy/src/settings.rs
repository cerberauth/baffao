use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::env;

use baffao_core::{
    oauth::OAuthConfig,
    settings::{JwtConfig, ServerConfig},
};

#[derive(Deserialize, Clone)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Deserialize, Clone)]
pub struct Settings {
    pub server: ServerConfig,
    pub oauth: OAuthConfig,
    pub jwt: Option<JwtConfig>,
    pub proxy: ProxyConfig,
    pub debug: bool,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        let s = Config::builder()
            .add_source(File::with_name("config/default"))
            .add_source(File::with_name(&format!("config/{}", run_mode)).required(false))
            .add_source(File::with_name("config/local").required(false))
            .add_source(Environment::with_prefix("baffao"))
            .build()?;

        println!("debug: {:?}", s.get_bool("debug"));

        s.try_deserialize()
    }
}
