use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;
use std::env;

use baffao::{
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
    pub proxy: Option<ProxyConfig>,
    pub debug: bool,
}

impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        let s = Config::builder()
            .add_source(File::with_name("config/default"))
            .add_source(File::with_name(&format!("config/{}", run_mode)).required(false))
            .add_source(File::with_name("config/local").required(false))
            .add_source(Environment::with_prefix("BAFFAO").separator("__"))
            .build()?;

        let debug = s.get_bool("debug").unwrap_or(false);
        println!("debug: {:?}", debug);
        if debug {
            println!("{:?}", s);
        }

        s.try_deserialize()
    }
}
