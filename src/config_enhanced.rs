use clap::Parser;
use std::path::PathBuf;

/// Enhanced Cryptoscan CLI arguments with validation
#[derive(Parser, Debug)]
#[command(name = "cryptoscan")]
#[command(about = "Scan code for cryptographic usage and hardcoded secrets", long_about = None)]
pub struct EnhancedConfig {
    /// Path to the folder or file to scan
    #[arg(short, long, default_value = "./src")]
    pub path: PathBuf,

    /// Output file path for findings (JSON format)
    #[arg(short, long, default_value = "web/data/findings.json")]
    pub output: PathBuf,

    /// Enable MIME-type based file filtering
    #[arg(long, default_value_t = false)]
    pub use_mime_filter: bool,

    /// Skip scanning for hardcoded secrets (API keys, tokens, passwords, etc.)
    #[arg(long, default_value_t = false)]
    pub skip_secrets: bool,

    /// Skip scanning for cryptographic libraries
    #[arg(long, default_value_t = false)]
    pub skip_libraries: bool,

    /// Skip scanning for keystore artifacts
    #[arg(long, default_value_t = false)]
    pub skip_keystores: bool,

    /// Maximum file size to scan (in MB)
    #[arg(long, default_value_t = 10)]
    pub max_file_size_mb: u64,

    /// Number of threads to use for parallel scanning
    #[arg(short, long)]
    pub threads: Option<usize>,

    /// Verbose logging
    #[arg(short, long, default_value_t = false)]
    pub verbose: bool,

    /// Only scan files modified in the last N days (for git repositories)
    #[arg(long)]
    pub recent_days: Option<u64>,
}

impl EnhancedConfig {
    /// Validate the configuration and return errors if invalid
    pub fn validate(&self) -> Result<(), String> {
        // Check if the scan path exists
        if !self.path.exists() {
            return Err(format!("Scan path does not exist: {}", self.path.display()));
        }

        // Check if the scan path is readable
        if let Err(e) = std::fs::metadata(&self.path) {
            return Err(format!("Cannot access scan path: {}", e));
        }

        // Validate output directory
        if let Some(parent) = self.output.parent() {
            if parent != PathBuf::from("") && !parent.exists() {
                // Try to create the output directory
                if let Err(e) = std::fs::create_dir_all(parent) {
                    return Err(format!("Cannot create output directory: {}", e));
                }
            }
        }

        // Validate thread count
        if let Some(threads) = self.threads {
            if threads == 0 {
                return Err("Thread count must be greater than 0".to_string());
            }
            if threads > 1000 {
                return Err("Thread count seems unreasonably high (max: 1000)".to_string());
            }
        }

        // Validate file size limit
        if self.max_file_size_mb == 0 {
            return Err("Maximum file size must be greater than 0".to_string());
        }
        if self.max_file_size_mb > 1000 {
            return Err("Maximum file size seems unreasonably high (max: 1000MB)".to_string());
        }

        Ok(())
    }

    /// Get the maximum file size in bytes
    pub fn max_file_size_bytes(&self) -> u64 {
        self.max_file_size_mb * 1024 * 1024
    }

    /// Check if any scanning is enabled
    pub fn has_scanning_enabled(&self) -> bool {
        !self.skip_secrets || !self.skip_libraries || !self.skip_keystores
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_config_validation() {
        let mut config = EnhancedConfig {
            path: PathBuf::from("src"), // This should exist in the test environment
            output: PathBuf::from("test_output.json"),
            use_mime_filter: false,
            skip_secrets: false,
            skip_libraries: false,
            skip_keystores: false,
            max_file_size_mb: 10,
            threads: Some(4),
            verbose: false,
            recent_days: None,
        };

        // Should be valid if src directory exists
        // assert!(config.validate().is_ok());

        // Test invalid thread count
        config.threads = Some(0);
        assert!(config.validate().is_err());

        // Test invalid file size
        config.threads = Some(4);
        config.max_file_size_mb = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_file_size_bytes_conversion() {
        let config = EnhancedConfig {
            path: PathBuf::from("."),
            output: PathBuf::from("output.json"),
            use_mime_filter: false,
            skip_secrets: false,
            skip_libraries: false,
            skip_keystores: false,
            max_file_size_mb: 5,
            threads: None,
            verbose: false,
            recent_days: None,
        };

        assert_eq!(config.max_file_size_bytes(), 5 * 1024 * 1024);
    }

    #[test]
    fn test_scanning_enabled() {
        let mut config = EnhancedConfig {
            path: PathBuf::from("."),
            output: PathBuf::from("output.json"),
            use_mime_filter: false,
            skip_secrets: true,
            skip_libraries: true,
            skip_keystores: true,
            max_file_size_mb: 10,
            threads: None,
            verbose: false,
            recent_days: None,
        };

        assert!(!config.has_scanning_enabled()); // All disabled

        config.skip_secrets = false;
        assert!(config.has_scanning_enabled()); // Secrets enabled
    }
}
