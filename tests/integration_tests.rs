use cryptoscan::config::Config;
use cryptoscan::scanner;
use cryptoscan::utils::report::Finding;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper function to create a temporary test file
fn create_test_file(dir: &TempDir, filename: &str, content: &str) -> PathBuf {
    let file_path = dir.path().join(filename);
    fs::write(&file_path, content).expect("Failed to write test file");
    file_path
}

/// Helper function to create a test configuration
fn create_test_config(path: &str) -> Config {
    Config {
        path: path.to_string(),
        use_mime_filter: false,
        skip_secrets: false,
    }
}

#[test]
fn test_crypto_library_detection() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Create test files with crypto library usage
    create_test_file(&temp_dir, "test.rs", r#"
use openssl::ssl::SslContext;
use ring::digest;
"#);
    
    create_test_file(&temp_dir, "test.py", r#"
import cryptography.fernet
from jwt import encode
"#);
    
    create_test_file(&temp_dir, "test.java", r#"
import javax.crypto.Cipher;
import org.bouncycastle.crypto.engines.AESEngine;
"#);

    let config = create_test_config(temp_dir.path().to_str().unwrap());
    
    // This would require the scan_directory function to return findings
    // For now, we test individual scanner components
    let rust_findings = cryptoscan::scanner::code::scan_file(&temp_dir.path().join("test.rs"));
    assert!(!rust_findings.is_empty());
    assert!(rust_findings.iter().any(|f| f.keyword == "openssl"));
    assert!(rust_findings.iter().any(|f| f.keyword == "ring"));
}

#[test]
fn test_secret_detection() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Create test file with various secrets
    create_test_file(&temp_dir, "secrets.py", r#"
# Real secrets (these should be detected)
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

# False positives (these should be ignored)
API_KEY = "your_api_key_here"
test_secret = "example_secret_for_testing"
dummy_token = "replace_with_real_token"
"#);

    let findings = cryptoscan::scanner::secrets::scan_file(&temp_dir.path().join("secrets.py"));
    
    // Should detect real secrets but not false positives
    let real_secrets: Vec<_> = findings.iter()
        .filter(|f| !f.keyword.contains("example") && !f.keyword.contains("test"))
        .collect();
    
    assert!(!real_secrets.is_empty(), "Should detect at least some real secrets");
    
    // Should filter out obvious false positives
    let false_positives: Vec<_> = findings.iter()
        .filter(|f| f.line_content.contains("your_api_key_here") || 
                   f.line_content.contains("example_secret_for_testing"))
        .collect();
    
    assert!(false_positives.is_empty(), "Should filter out obvious false positives");
}

#[test]
fn test_keystore_file_detection() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Create keystore files
    create_test_file(&temp_dir, "server.pem", "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----");
    create_test_file(&temp_dir, "keystore.jks", "binary keystore content");
    create_test_file(&temp_dir, "private.key", "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----");
    
    let pem_finding = cryptoscan::scanner::artefacts::scan_keystore_file(&temp_dir.path().join("server.pem"));
    assert!(pem_finding.is_some());
    assert_eq!(pem_finding.unwrap().category, "keystore");
    
    let jks_finding = cryptoscan::scanner::artefacts::scan_keystore_file(&temp_dir.path().join("keystore.jks"));
    assert!(jks_finding.is_some());
    assert_eq!(jks_finding.unwrap().keyword, "jks");
}

#[test]
fn test_key_command_detection() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    create_test_file(&temp_dir, "setup.sh", r#"
#!/bin/bash
# Generate SSL certificate
openssl genpkey -algorithm RSA -out private.key
openssl req -new -x509 -key private.key -out cert.pem

# Setup SSH keys
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa

# AWS KMS operations
aws kms create-key --description "My test key"
"#);

    let findings = cryptoscan::scanner::artefacts::scan_key_commands(&temp_dir.path().join("setup.sh"));
    
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.keyword.contains("openssl genpkey")));
    assert!(findings.iter().any(|f| f.keyword.contains("ssh-keygen")));
    assert!(findings.iter().any(|f| f.keyword.contains("aws kms")));
}

#[test]
fn test_comment_filtering() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    create_test_file(&temp_dir, "commented.py", r#"
# This is a comment with API_KEY = "fake_key_in_comment"
// Another comment style with secret = "commented_secret"
api_key = "real_secret_12345678901234567890"  # This should be detected
# password = "this_should_be_ignored"
"#);

    let findings = cryptoscan::scanner::secrets::scan_file(&temp_dir.path().join("commented.py"));
    
    // Should only detect the uncommented secret
    assert_eq!(findings.len(), 1);
    assert!(findings[0].line_content.contains("real_secret"));
}

#[test]
fn test_language_detection() {
    use cryptoscan::utils::lang_ident::detect_language;
    
    assert_eq!(detect_language(&PathBuf::from("test.rs")), "Rust");
    assert_eq!(detect_language(&PathBuf::from("test.py")), "Python");
    assert_eq!(detect_language(&PathBuf::from("test.java")), "Java");
    assert_eq!(detect_language(&PathBuf::from("test.js")), "JavaScript");
    assert_eq!(detect_language(&PathBuf::from("test.ts")), "TypeScript");
    assert_eq!(detect_language(&PathBuf::from("Dockerfile")), "Dockerfile");
    assert_eq!(detect_language(&PathBuf::from("Makefile")), "Makefile");
    assert_eq!(detect_language(&PathBuf::from(".env")), "Environment");
}

#[test]
fn test_file_size_limits() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Create a large file (this is a simplified test)
    let large_content = "a".repeat(1000); // 1KB file for testing
    create_test_file(&temp_dir, "large.py", &large_content);
    
    let findings = cryptoscan::scanner::secrets::scan_file(&temp_dir.path().join("large.py"));
    // Should complete without crashing (actual size limit is 10MB)
    assert!(findings.is_empty()); // No secrets in repetitive content
}

#[test]
fn test_regex_safety() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // Create file with potentially problematic content for regex
    create_test_file(&temp_dir, "complex.txt", &"x".repeat(50000)); // Very long line
    
    let findings = cryptoscan::scanner::secrets::scan_file(&temp_dir.path().join("complex.txt"));
    // Should complete without crashing due to line length limits
    assert!(findings.is_empty());
}
