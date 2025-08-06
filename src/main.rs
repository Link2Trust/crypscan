mod config;
mod scanner;
mod utils;

use crate::config::Cli;
use crate::scanner::code::scan_directory;
use crate::utils::report::write_findings_to_file;
use clap::Parser;
use std::path::Path;

fn main() {
    let args = Cli::parse();
    let path = Path::new(&args.path);

    println!("🔐 Scanning path: {}", path.display());

    if !path.exists() {
        eprintln!("❌ Error: Path does not exist.");
        std::process::exit(1);
    }

    let findings = scan_directory(path);

    if findings.is_empty() {
        println!("✅ No crypto-related patterns found.");
    } else {
        let output_file = "web/data/findings.json";
        if let Err(e) = write_findings_to_file(&findings, output_file) {
            eprintln!("❌ Failed to write report: {}", e);
        } else {
            println!("✅ JSON report written to {}", output_file);
        }
    }
}
