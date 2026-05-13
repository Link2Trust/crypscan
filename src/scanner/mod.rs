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
    let entries = collect_scannable_entries(&config.path);
    let pb = create_progress_bar(entries.len());
    let findings = scan_entries_parallel(entries, config, &pb);
    
    pb.finish_with_message("✅ Scan complete");
    write_findings_to_output(&findings, &config.path)?;
    
    Ok(())
}

/// Collect all scannable entries from the given path
fn collect_scannable_entries(path: &str) -> Vec<walkdir::DirEntry> {
    WalkDir::new(path)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .filter(is_not_in_ignored_folder)
        .filter(|e| is_scannable_file(e.path()))
        .collect()
}

/// Create and configure the progress bar
fn create_progress_bar(total: usize) -> ProgressBar {
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("🔍 Scanning [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb
}

/// Scan entries in parallel and collect findings
fn scan_entries_parallel(entries: Vec<walkdir::DirEntry>, config: &Config, pb: &ProgressBar) -> Vec<Finding> {
    entries
        .par_iter()
        .filter_map(|entry| scan_single_file(entry.path(), config, pb))
        .flatten()
        .collect()
}

/// Scan a single file and return findings
fn scan_single_file(path: &Path, config: &Config, pb: &ProgressBar) -> Option<Vec<Finding>> {
    if should_skip_mime_filter(path, config) {
        pb.inc(1);
        return None;
    }

    let results = collect_findings_from_scanners(path, config);
    pb.inc(1);
    Some(results)
}

/// Check if file should be skipped due to MIME filtering
fn should_skip_mime_filter(path: &Path, config: &Config) -> bool {
    if !config.use_mime_filter {
        return false;
    }
    
    let skip_mime_prefixes = ["text/markdown", "text/plain", "application/log"];
    
    if let Some(mime) = detect_mime_type(path) {
        skip_mime_prefixes.iter().any(|prefix| mime.starts_with(prefix))
    } else {
        false
    }
}

/// Collect findings from all relevant scanners for a single file
fn collect_findings_from_scanners(path: &Path, config: &Config) -> Vec<Finding> {
    let mut results = Vec::new();

    // Scan for keystore files
    if let Some(keystore) = scan_keystore_file(path) {
        results.push(keystore);
    }

    // Scan code files
    if is_supported_code_file(path) {
        results.extend(crate::scanner::code::scan_file(path));
        results.extend(scan_key_commands(path));
        
        if !config.skip_secrets {
            results.extend(crate::scanner::secrets::scan_file(path));
        }
    }
    
    // Scan config files for secrets only
    if is_config_file(path) && !config.skip_secrets {
        results.extend(crate::scanner::secrets::scan_file(path));
    }

    results
}

/// Write findings to the output file
fn write_findings_to_output(findings: &[Finding], scan_path: &str) -> io::Result<()> {
    // Always write to web/data for the dashboard
    let dashboard_path = "web/data/findings.json";
    if let Some(parent) = Path::new(dashboard_path).parent() {
        fs::create_dir_all(parent)?;
    }
    write_report_to_json(findings, dashboard_path)?;
    println!("✅ Findings written to {}", dashboard_path);

    // Also save in the target application path
    let target_dir = Path::new(scan_path);
    let target_path = if target_dir.is_dir() {
        target_dir.join("findings.json")
    } else {
        target_dir.parent().unwrap_or(Path::new(".")).join("findings.json")
    };
    write_report_to_json(findings, &target_path)?;
    println!("✅ Findings written to {}", target_path.display());
    
    Ok(())
}
