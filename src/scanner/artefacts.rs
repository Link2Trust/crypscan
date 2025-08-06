use crate::utils::file_utils::read_file_to_string;
use crate::utils::report::Finding;
use std::path::Path;

const KEYSTORE_EXTENSIONS: &[(&str, &str)] = &[
    ("pem", "PEM file"),
    ("crt", "X.509 cert"),
    ("cer", "X.509 cert"),
    ("key", "Private key"),
    ("jks", "Java Keystore"),
    ("p12", "PKCS#12 Keystore"),
    ("pfx", "PKCS#12 Keystore"),
    ("asc", "GPG key"),
    ("gpg", "GPG encrypted"),
    ("der", "DER binary cert")
];

const KEY_COMMAND_PATTERNS: &[(&str, &str, &str)] = &[
    ("openssl genpkey", "OpenSSL", "Shell"),
    ("openssl rsa", "OpenSSL", "Shell"),
    ("keytool -genkey", "keytool", "Shell"),
    ("gpg --gen-key", "GPG", "Shell"),
    ("gpg --import", "GPG", "Shell"),
    ("ssh-keygen", "SSH", "Shell"),
    ("az keyvault", "Azure Key Vault", "Shell"),
    ("aws kms", "AWS KMS", "Shell"),
    ("vault kv", "HashiCorp Vault", "Shell"),
    ("cfssl genkey", "CFSSL", "Shell"),
];

/// Detect keystore files by extension
pub fn scan_keystore_file(path: &Path) -> Option<Finding> {
    path.extension()
        .and_then(|ext| ext.to_str())
        .and_then(|ext| {
            let ext = ext.to_lowercase();
            for (key_ext, label) in KEYSTORE_EXTENSIONS {
                if ext == *key_ext {
                    return Some(Finding {
                        file: path.display().to_string(),
                        line_number: 0,
                        line_content: "".to_string(),
                        match_type: "keystore".to_string(),
                        keyword: key_ext.to_string(),
                        context: label.to_string(),
                        version: None,
                        language: "Binary/File".to_string(),
                        source: "file extension".to_string(),
                        category: "keystore".to_string(),
                    });
                }
            }
            None
        })
}

/// Detect CLI key management commands in plaintext/script files
pub fn scan_key_commands(path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(content) = read_file_to_string(path) {
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with('*') {
                continue;
            }

            for (pattern, label, language) in KEY_COMMAND_PATTERNS {
                if line.contains(pattern) {
                    findings.push(Finding {
                        file: path.display().to_string(),
                        line_number: i + 1,
                        line_content: line.to_string(),
                        match_type: "command".to_string(),
                        keyword: pattern.to_string(),
                        context: label.to_string(),
                        version: None,
                        language: language.to_string(),
                        source: "command".to_string(),
                        category: "key-command".to_string(),
                    });
                }
            }
        }
    }

    findings
}
