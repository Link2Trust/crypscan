use clap::Parser;

/// Cryptoscan CLI arguments
#[derive(Parser, Debug)]
#[command(name = "cryptoscan")]
#[command(about = "Scan code for cryptographic usage", long_about = None)]
pub struct Config {
    /// Path to the folder or file to scan
    #[arg(short, long, default_value = "./src")]
    pub path: String,

    /// Enable MIME-type based file filtering
    #[arg(long, default_value_t = false)]
    pub use_mime_filter: bool,
}
