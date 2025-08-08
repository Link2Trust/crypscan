pub mod code;
pub mod binary;
pub mod network;
pub mod artefacts;
pub mod secrets;

use crate::config::Config;
use crate::scanner::artefacts::{scan_keystore_file, scan_key_commands};
use crate::utils::file_utils::detect_mime_type;
use crate::utils::report::{write_report_to_json, Finding};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::path::Path;
use walkdir::{DirEntry, WalkDir};

fn is_supported_code_file(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => {
            let ext = ext.to_lowercase();
            matches!(
                ext.as_str(),
                "rs" | "py" | "java" | "js" | "ts" | "mjs" |
                "go" | "c" | "cpp" | "h" | "hpp" |
                "php" | "cs" | "kt" | "kts" |
                "swift" | "scala" | "rb" |
                "sh" | "ps1" | "cmd"
            )
        }
        None => false,
    }
}

fn is_config_file(path: &Path) -> bool {
    // Check by extension
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext = ext.to_lowercase();
        if matches!(ext.as_str(), "env" | "yml" | "yaml" | "json" | "toml" | "ini" | "conf" | "config" | "properties") {
            return true;
        }
    }
    
    // Check by filename
    if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
        let filename = filename.to_lowercase();
        matches!(filename.as_str(), 
            ".env" | ".env.local" | ".env.development" | ".env.production" | ".env.test" |
            "config" | "secrets" | "credentials" | "settings"
        )
    } else {
        false
    }
}

fn is_not_in_ignored_folder(entry: &DirEntry) -> bool {
    let ignored_folders = [
        "css", "style", "styles", "scss", "less", "assets",
        "node_modules", "vendor", "dist", "build", "target", ".git", ".idea"
    ];
    let path = entry.path();

    for component in path.components() {
        if let Some(folder) = component.as_os_str().to_str() {
            if ignored_folders.iter().any(|f| folder.eq_ignore_ascii_case(f)) {
                return false;
            }
        }
    }

    true
}

pub fn scan_directory(config: &Config) {
    let skip_mime_prefixes = vec!["text/markdown", "text/plain", "application/log"];

    let entries: Vec<_> = WalkDir::new(&config.path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .filter(is_not_in_ignored_folder)
        .collect();

    let pb = ProgressBar::new(entries.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("🔍 Scanning [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files")
            .unwrap()
            .progress_chars("=>-"),
    );

    let findings: Vec<Finding> = entries
        .par_iter()
        .filter_map(|entry| {
            let path = entry.path();

            if config.use_mime_filter {
                if let Some(mime) = detect_mime_type(path) {
                    if skip_mime_prefixes.iter().any(|prefix| mime.starts_with(prefix)) {
                        pb.inc(1);
                        return None;
                    }
                }
            }

            // Collect all findings from all scanners
            let mut results = Vec::new();

            if let Some(keystore) = scan_keystore_file(path) {
                results.push(keystore);
            }

            if is_supported_code_file(path) {
                results.extend(crate::scanner::code::scan_file(path));
                results.extend(scan_key_commands(path));
                
                // Scan for secrets if enabled
                if config.scan_secrets && !config.skip_secrets {
                    results.extend(crate::scanner::secrets::scan_file(path));
                }
            }
            
            // Scan config files for secrets (but not for crypto libraries) if enabled
            if is_config_file(path) && config.scan_secrets && !config.skip_secrets {
                results.extend(crate::scanner::secrets::scan_file(path));
            }

            pb.inc(1);
            Some(results)
        })
        .flatten()
        .collect();

    pb.finish_with_message("✅ Scan complete");

    if let Err(err) = write_report_to_json(&findings, "web/data/findings.json") {
        eprintln!("❌ Failed to write findings.json: {}", err);
    } else {
        println!("✅ Findings written to web/data/findings.json");
    }
}
