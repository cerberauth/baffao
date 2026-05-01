use clap::Parser;

/// CLI arguments for the Baffao server
#[derive(Parser, Debug)]
#[clap(
    name = "baffao-server",
    version = env!("CARGO_PKG_VERSION"),
    author = "Baffao Contributors",
    about = "HTTP server for OAuth 2.0 Backend For Frontend (BFF) and Token-Mediating Backend"
)]
pub struct Cli {
    /// Path to the configuration file
    #[clap(short, long, env = "BAFFAO_CONFIG")]
    pub config_file: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[clap(long, env = "BAFFAO_LOG_LEVEL")]
    pub log_level: Option<String>,
}
