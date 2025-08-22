use std::fmt;
use std::io;

/// Custom error types for CryptoScanner
#[derive(Debug)]
pub enum ScanError {
    /// IO-related errors (file access, directory creation, etc.)
    Io(io::Error),
    /// Configuration validation errors
    Config(String),
    /// Regex compilation errors
    Regex(regex::Error),
    /// JSON serialization/deserialization errors
    Json(serde_json::Error),
    /// File processing errors
    FileProcessing(String),
    /// Scanner-specific errors
    Scanner(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Io(err) => write!(f, "IO error: {}", err),
            ScanError::Config(msg) => write!(f, "Configuration error: {}", msg),
            ScanError::Regex(err) => write!(f, "Regex error: {}", err),
            ScanError::Json(err) => write!(f, "JSON error: {}", err),
            ScanError::FileProcessing(msg) => write!(f, "File processing error: {}", msg),
            ScanError::Scanner(msg) => write!(f, "Scanner error: {}", msg),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<io::Error> for ScanError {
    fn from(err: io::Error) -> Self {
        ScanError::Io(err)
    }
}

impl From<regex::Error> for ScanError {
    fn from(err: regex::Error) -> Self {
        ScanError::Regex(err)
    }
}

impl From<serde_json::Error> for ScanError {
    fn from(err: serde_json::Error) -> Self {
        ScanError::Json(err)
    }
}

/// Result type alias for CryptoScanner operations
pub type ScanResult<T> = Result<T, ScanError>;

/// Utility function to create configuration errors
pub fn config_error(msg: &str) -> ScanError {
    ScanError::Config(msg.to_string())
}

/// Utility function to create file processing errors
pub fn file_error(msg: &str) -> ScanError {
    ScanError::FileProcessing(msg.to_string())
}

/// Utility function to create scanner errors
pub fn scanner_error(msg: &str) -> ScanError {
    ScanError::Scanner(msg.to_string())
}
