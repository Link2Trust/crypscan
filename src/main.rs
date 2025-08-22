use cryptoscan::config::Config;
use cryptoscan::scanner::scan_directory;
use clap::Parser;
use log::{info, error};
use std::process;
use std::path::PathBuf;

#[cfg(feature = "server")]
use cryptoscan::server::start_server;

#[tokio::main]
async fn main() {
    // Initialize logger
    env_logger::init();
    
    let config = Config::parse();
    
    if config.serve {
        // Server mode
        info!("Starting CryptoScanner web server on port {}", config.port);
        info!("Web directory: {}", config.web_dir);
        
        let web_dir = PathBuf::from(&config.web_dir);
        
        if !web_dir.exists() {
            error!("Web directory does not exist: {}", config.web_dir);
            process::exit(1);
        }
        
        #[cfg(feature = "server")]
        {
            if let Err(e) = start_server(config.port, web_dir).await {
                error!("Server failed to start: {}", e);
                process::exit(1);
            }
        }
        
        #[cfg(not(feature = "server"))]
        {
            error!("Server feature not enabled. Please compile with --features server");
            process::exit(1);
        }
    } else {
        // CLI mode (existing functionality)
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
}

