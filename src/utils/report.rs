use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct Finding {
    pub file: String,
    pub line_number: usize,
    pub line_content: String,
    pub match_type: String,
    pub keyword: String,
    pub context: String,
    pub version: Option<String>,
    pub language: String,
    pub source: String,
    pub category: String, // ✅ NEW: library, keystore, command, etc.
}

pub fn write_report_to_json<P: AsRef<Path>>(findings: &[Finding], output_path: P) -> std::io::Result<()> {
    let json = serde_json::to_string_pretty(findings)?;
    let mut file = File::create(output_path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}
