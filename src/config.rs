use clap::Parser;

/// Cryptoscan CLI arguments
#[derive(Parser, Debug)]
#[command(name = "cryptoscan")]
#[command(about = "Scan code for cryptographic usage and hardcoded secrets", long_about = None)]
pub struct Config {
    /// Path to the folder or file to scan
    #[arg(short, long, default_value = "./src")]
    pub path: String,

    /// Enable MIME-type based file filtering
    #[arg(long, default_value_t = false)]
    pub use_mime_filter: bool,

    /// Skip scanning for hardcoded secrets (API keys, tokens, passwords, etc.)
    #[arg(long, default_value_t = false)]
    pub skip_secrets: bool,

    /// Start web server mode instead of CLI scan
    #[arg(long, default_value_t = false)]
    pub serve: bool,

    /// Port for web server (only used with --serve)
    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    /// Path to web assets directory (only used with --serve)
    #[arg(long, default_value = "./web")]
    pub web_dir: String,
}
