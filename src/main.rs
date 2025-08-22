use cryptoscan::config::Config;
use cryptoscan::scanner::scan_directory;
use clap::Parser;
use log::{info, error};
use std::process;

fn main() {
    // Initialize logger
    env_logger::init();
    
    let config = Config::parse();
    
    info!("Starting CryptoScanner with path: {}", config.path);
    info!("MIME filtering: {}", config.use_mime_filter);
    info!("Skip secrets: {}", config.skip_secrets);
    
    match scan_directory(&config) {
        Ok(()) => {
            info!("Scan completed successfully");
        },
        Err(e) => {
            error!("Scan failed: {}", e);
            process::exit(1);
        }
    }
}

