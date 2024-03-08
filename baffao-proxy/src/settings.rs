use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::env;

use baffao_core::settings::{JwtConfig, OAuthConfig, ServerConfig};

#[derive(Debug, Deserialize, Clone)]
#[allow(unused)]
pub struct Settings {
    pub server: ServerConfig,
    pub oauth: OAuthConfig,
    pub jwt: Option<JwtConfig>,
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
