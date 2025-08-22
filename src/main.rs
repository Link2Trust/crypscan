use cryptoscan::config::Config;
use cryptoscan::scanner::scan_directory;
use cryptoscan::cbom::{CbomGenerator, CbomDocument};
use clap::Parser;
use log::{info, error};
use std::process;
use std::path::PathBuf;
use std::fs;

#[cfg(feature = "server")]
use cryptoscan::server::start_server;

#[cfg(feature = "server")]
#[tokio::main]
async fn main() {
    run_main().await;
}

#[cfg(not(feature = "server"))]
fn main() {
    run_main_sync();
}

#[cfg(feature = "server")]
async fn run_main() {
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
                
                // Generate CBOM if requested
                if config.cbom {
                    if let Err(e) = generate_cbom_report(&config) {
                        error!("Failed to generate CBOM: {}", e);
                        process::exit(1);
                    }
                }
            },
            Err(e) => {
                error!("Scan failed: {}", e);
                process::exit(1);
            }
        }
    }
}

#[cfg(not(feature = "server"))]
fn run_main_sync() {
    // Initialize logger
    env_logger::init();
    
    let config = Config::parse();
    
    if config.serve {
        error!("Server feature not enabled. Please compile with --features server");
        process::exit(1);
    } else {
        // CLI mode (existing functionality)
        info!("Starting CryptoScanner with path: {}", config.path);
        info!("MIME filtering: {}", config.use_mime_filter);
        info!("Skip secrets: {}", config.skip_secrets);
        
        match scan_directory(&config) {
            Ok(()) => {
                info!("Scan completed successfully");
                
                // Generate CBOM if requested
                if config.cbom {
                    if let Err(e) = generate_cbom_report(&config) {
                        error!("Failed to generate CBOM: {}", e);
                        process::exit(1);
                    }
                }
            },
            Err(e) => {
                error!("Scan failed: {}", e);
                process::exit(1);
            }
        }
    }
}

/// Generate and export CBOM report
fn generate_cbom_report(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    info!("Generating CycloneDX CBOM report...");
    
    // Load scan findings from the generated JSON file
    let findings_path = "web/data/findings.json";
    if !std::path::Path::new(findings_path).exists() {
        return Err("Scan findings file not found. Please run a scan first.".into());
    }
    
    let findings_json = fs::read_to_string(findings_path)?;
    let findings: Vec<cryptoscan::utils::report::Finding> = serde_json::from_str(&findings_json)?;
    
    info!("Loaded {} findings for CBOM generation", findings.len());
    
    // Generate CBOM document
    let cbom = CbomGenerator::generate_cbom(&findings, config.app_name.clone())?;
    
    // Export in requested format
    let output_content = match config.cbom_format.to_lowercase().as_str() {
        "json" => CbomGenerator::export_json(&cbom)?,
        "xml" => CbomGenerator::export_xml(&cbom)?,
        format => {
            error!("Unsupported CBOM format: {}. Supported formats: json, xml", format);
            return Err(format!("Unsupported format: {}", format).into());
        }
    };
    
    // Write CBOM to file
    fs::write(&config.cbom_output, output_content)?;
    
    info!("CBOM report generated successfully: {}", config.cbom_output);
    info!("Format: {}", config.cbom_format);
    
    if let Some(app_name) = &config.app_name {
        info!("Application: {}", app_name);
    }
    
    // Print summary
    print_cbom_summary(&cbom);
    
    Ok(())
}

/// Print CBOM generation summary
fn print_cbom_summary(cbom: &CbomDocument) {
    println!("\n📋 CBOM Generation Summary");
    println!("├─ Spec Version: {}", cbom.spec_version);
    println!("├─ Document Version: {}", cbom.version);
    println!("├─ Target Component: {}", cbom.metadata.component.name);
    println!("├─ Components Found: {}", cbom.components.len());
    
    // Component breakdown
    let mut component_types = std::collections::HashMap::new();
    for component in &cbom.components {
        *component_types.entry(&component.component_type).or_insert(0) += 1;
    }
    
    for (comp_type, count) in component_types {
        println!("│  ├─ {}: {}", comp_type, count);
    }
    
    // Risk assessments
    if let Some(declarations) = &cbom.declarations {
        if let Some(risks) = &declarations.risk_assessments {
            println!("├─ Risk Assessments: {}", risks.len());
            for risk in risks {
                println!("│  ├─ {}: {} ({})", risk.category, risk.level, risk.description);
            }
        }
    }
    
    println!("└─ Generated: {}", cbom.metadata.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
    println!();
}

