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
use std::{fs, io};
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

fn is_scannable_file(path: &Path) -> bool {
    // Check if it's a supported code file, config file, or potential keystore file
    is_supported_code_file(path) || is_config_file(path) || has_keystore_extension(path)
}

fn has_keystore_extension(path: &Path) -> bool {
    const KEYSTORE_EXTENSIONS: &[&str] = &[
        "pem", "crt", "cer", "key", "jks", "p12", "pfx", "asc", "gpg", "der"
    ];
    
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext = ext.to_lowercase();
        KEYSTORE_EXTENSIONS.iter().any(|&keystore_ext| ext == keystore_ext)
    } else {
        false
    }
}

pub fn scan_directory(config: &Config) -> io::Result<()> {
    let skip_mime_prefixes = vec!["text/markdown", "text/plain", "application/log"];

    let entries: Vec<_> = WalkDir::new(&config.path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .filter(is_not_in_ignored_folder)
        .filter(|e| is_scannable_file(e.path()))
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
                
                // Scan for secrets unless explicitly skipped
                if !config.skip_secrets {
                    results.extend(crate::scanner::secrets::scan_file(path));
                }
            }
            
            // Scan config files for secrets (but not for crypto libraries) unless explicitly skipped
            if is_config_file(path) && !config.skip_secrets {
                results.extend(crate::scanner::secrets::scan_file(path));
            }

            pb.inc(1);
            Some(results)
        })
        .flatten()
        .collect();

    pb.finish_with_message("✅ Scan complete");

    // Ensure output directory exists
    let output_path = "web/data/findings.json";
    if let Some(parent) = Path::new(output_path).parent() {
        fs::create_dir_all(parent)?;
    }

    write_report_to_json(&findings, output_path)?;
    println!("✅ Findings written to {}", output_path);
    
    Ok(())
}
