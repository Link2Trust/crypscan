use clap::Parser;

/// Cryptoscan CLI arguments
#[derive(Parser, Debug)]
#[command(name = "cryptoscan")]
#[command(about = "Scan code for cryptographic usage", long_about = None)]
pub struct Cli {
    /// Path to the folder or file to scan
    #[arg(short, long, default_value = "./src")]
    pub path: String,
}
