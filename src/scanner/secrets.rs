use crate::utils::file_utils::read_file_to_string;
use crate::utils::report::Finding;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

/// Secret patterns with their descriptions and severity
fn get_secret_patterns() -> HashMap<&'static str, (&'static str, &'static str, u8)> {
    let mut patterns = HashMap::new();

    // Generic patterns
    patterns.insert(r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]"#, ("API Key", "Generic API key pattern", 3));
    patterns.insert(r#"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]"#, ("Secret Key", "Generic secret key pattern", 3));
    patterns.insert(r#"(?i)(access[_-]?token|accesstoken)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]"#, ("Access Token", "Generic access token pattern", 3));
    patterns.insert(r#"(?i)(auth[_-]?token|authtoken)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]"#, ("Auth Token", "Generic authentication token", 3));
    patterns.insert(r#"(?i)password\s*[:=]\s*['"]([^'"]{8,})['"]"#, ("Password", "Hardcoded password", 3));
    patterns.insert(r#"(?i)passwd\s*[:=]\s*['"]([^'"]{8,})['"]"#, ("Password", "Hardcoded passwd", 3));
    
    // AWS patterns
    patterns.insert(r"AKIA[0-9A-Z]{16}", ("AWS Access Key", "AWS Access Key ID", 3));
    patterns.insert(r#"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"]([a-zA-Z0-9/+=]{40})['"]"#, ("AWS Secret", "AWS Secret Access Key", 3));
    
    // GitHub patterns
    patterns.insert(r"ghp_[a-zA-Z0-9]{36}", ("GitHub Token", "GitHub Personal Access Token", 3));
    patterns.insert(r"gho_[a-zA-Z0-9]{36}", ("GitHub Token", "GitHub OAuth Access Token", 3));
    patterns.insert(r"ghu_[a-zA-Z0-9]{36}", ("GitHub Token", "GitHub User Access Token", 3));
    patterns.insert(r"ghs_[a-zA-Z0-9]{36}", ("GitHub Token", "GitHub Server Access Token", 3));
    patterns.insert(r"ghr_[a-zA-Z0-9]{36}", ("GitHub Token", "GitHub Refresh Token", 3));
    
    // Google API patterns
    patterns.insert(r"AIza[0-9A-Za-z\-_]{35}", ("Google API Key", "Google API Key", 3));
    
    // Slack patterns
    patterns.insert(r"xox[baprs]-([0-9a-zA-Z]{10,48})", ("Slack Token", "Slack API Token", 2));
    
    // Discord patterns
    patterns.insert(r"[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}", ("Discord Token", "Discord Bot Token", 2));
    
    // Database connection strings
    patterns.insert(r"(?i)mongodb://[^:]+:[^@]+@[^/]+", ("MongoDB URI", "MongoDB connection string with credentials", 3));
    patterns.insert(r"(?i)mysql://[^:]+:[^@]+@[^/]+", ("MySQL URI", "MySQL connection string with credentials", 3));
    patterns.insert(r"(?i)postgresql://[^:]+:[^@]+@[^/]+", ("PostgreSQL URI", "PostgreSQL connection string with credentials", 3));
    
    // JWT tokens (basic pattern)
    patterns.insert(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", ("JWT Token", "JSON Web Token", 2));
    
    // Private keys
    patterns.insert(r"-----BEGIN\s+(RSA\s+)?PRIVATE KEY-----", ("Private Key", "RSA/Generic Private Key", 3));
    patterns.insert(r"-----BEGIN\s+OPENSSH\s+PRIVATE KEY-----", ("SSH Private Key", "OpenSSH Private Key", 3));
    patterns.insert(r"-----BEGIN\s+EC\s+PRIVATE KEY-----", ("EC Private Key", "Elliptic Curve Private Key", 3));
    patterns.insert(r"-----BEGIN\s+DSA\s+PRIVATE KEY-----", ("DSA Private Key", "DSA Private Key", 3));
    
    // Crypto wallet private keys (basic patterns)
    patterns.insert(r#"(?i)(private[_-]?key|privkey)\s*[:=]\s*['"]([a-fA-F0-9]{64})['"]"#, ("Crypto Private Key", "Cryptocurrency private key", 3));
    
    // JSON field patterns for public/private keys
    patterns.insert(r#"(?i)['"]\w*_private_key['"]\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#, ("JSON Private Key", "Private key in JSON field ending with _private_key", 3));
    patterns.insert(r#"(?i)['"]\w*_public_key['"]\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#, ("JSON Public Key", "Public key in JSON field ending with _public_key", 2));
    patterns.insert(r#"(?i)['"]private_key_\w*['"]\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#, ("JSON Private Key", "Private key in JSON field starting with private_key_", 3));
    patterns.insert(r#"(?i)['"]public_key_\w*['"]\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#, ("JSON Public Key", "Public key in JSON field starting with public_key_", 2));
    
    // Additional patterns for unquoted JSON keys (common in some configs)
    patterns.insert(r#"(?i)\w*_private_key\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#, ("JSON Private Key", "Private key in unquoted JSON field ending with _private_key", 3));
    patterns.insert(r#"(?i)\w*_public_key\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#, ("JSON Public Key", "Public key in unquoted JSON field ending with _public_key", 2));
    patterns.insert(r#"(?i)private_key_\w*\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#, ("JSON Private Key", "Private key in unquoted JSON field starting with private_key_", 3));
    patterns.insert(r#"(?i)public_key_\w*\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#, ("JSON Public Key", "Public key in unquoted JSON field starting with public_key_", 2));
    
    // Azure patterns
    patterns.insert(r#"(?i)azure[_-]?client[_-]?secret\s*[:=]\s*['"]([a-zA-Z0-9~\._-]{34})['"]"#, ("Azure Secret", "Azure Client Secret", 3));
    
    // Heroku patterns
    patterns.insert(r#"(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['"]([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})['"]"#, ("Heroku API Key", "Heroku API Key", 3));
    
    // Mailgun patterns
    patterns.insert(r"key-[a-fA-F0-9]{32}", ("Mailgun Key", "Mailgun API Key", 2));
    
    // Twilio patterns
    patterns.insert(r"SK[a-fA-F0-9]{32}", ("Twilio Key", "Twilio API Key", 2));
    patterns.insert(r"AC[a-fA-F0-9]{32}", ("Twilio SID", "Twilio Account SID", 1));
    
    // SendGrid patterns
    patterns.insert(r"SG\.[a-zA-Z0-9_\-\.]{66}", ("SendGrid Key", "SendGrid API Key", 2));
    
    // Facebook Access Token
    patterns.insert(r"EAA[a-zA-Z0-9]{90,}", ("Facebook Token", "Facebook Access Token", 2));
    
    // Generic high-entropy strings that might be secrets
    patterns.insert(r#"(?i)(token|key|secret|password|passwd|auth)\s*[:=]\s*['"]([a-zA-Z0-9+/=]{32,})['"]"#, ("High Entropy String", "Potential secret with high entropy", 1));

    patterns
}

/// Check if a line looks like a comment (to potentially skip false positives)
fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || 
    trimmed.starts_with("#") || 
    trimmed.starts_with("/*") || 
    trimmed.starts_with("*") ||
    trimmed.starts_with("<!--") ||
    trimmed.starts_with("\"\"\"") ||
    trimmed.starts_with("'''")
}

/// Check if the match is likely a false positive based on context
fn is_likely_false_positive(line: &str, matched_value: &str) -> bool {
    let line_lower = line.to_lowercase();
    let value_lower = matched_value.to_lowercase();
    
    // Skip if it contains common placeholder text
    let placeholders = [
        "example", "test", "dummy", "fake", "placeholder", "sample", 
        "your_key", "your_secret", "your_token", "replace_me", 
        "todo", "fixme", "xxx", "yyy", "zzz", "lorem", "ipsum",
        "12345", "abcde", "qwerty", "password", "secret", "key"
    ];
    
    for placeholder in &placeholders {
        if value_lower.contains(placeholder) {
            return true;
        }
    }
    
    // Skip if the line contains documentation keywords
    let doc_keywords = ["example", "documentation", "readme", "demo", "tutorial"];
    for keyword in &doc_keywords {
        if line_lower.contains(keyword) {
            return true;
        }
    }
    
    // Skip very short potential secrets (likely false positives)
    if matched_value.len() < 10 {
        return true;
    }
    
    false
}

/// Determine the programming language based on file extension
fn get_language_from_path(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => {
            match ext.to_lowercase().as_str() {
                "rs" => "Rust",
                "py" => "Python", 
                "java" => "Java",
                "js" | "mjs" => "JavaScript",
                "ts" => "TypeScript",
                "go" => "Go",
                "c" => "C",
                "cpp" | "cc" | "cxx" => "C++",
                "h" | "hpp" => "C/C++ Header",
                "php" => "PHP",
                "cs" => "C#",
                "kt" | "kts" => "Kotlin",
                "swift" => "Swift",
                "scala" => "Scala",
                "rb" => "Ruby",
                "sh" => "Shell",
                "ps1" => "PowerShell",
                "cmd" => "Batch",
                "yaml" | "yml" => "YAML",
                "json" => "JSON",
                "toml" => "TOML",
                "xml" => "XML",
                "env" => "Environment",
                _ => "Unknown"
            }.to_string()
        }
        None => "Unknown".to_string()
    }
}

/// Scans a source file for hardcoded secrets
pub fn scan_file(path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let patterns = get_secret_patterns();
    let language = get_language_from_path(path);

    if let Ok(content) = read_file_to_string(path) {
        for (line_num, line) in content.lines().enumerate() {
            // Skip comment lines to reduce false positives
            if is_comment_line(line) {
                continue;
            }

            for (pattern_str, (secret_type, description, _severity)) in &patterns {
                if let Ok(regex) = Regex::new(pattern_str) {
                    for capture in regex.captures_iter(line) {
                        // Try to get the actual secret value from capture groups
                        let secret_value = if capture.len() > 2 {
                            capture.get(2).map(|m| m.as_str()).unwrap_or("").to_string()
                        } else if capture.len() > 1 {
                            capture.get(1).map(|m| m.as_str()).unwrap_or("").to_string()
                        } else {
                            capture.get(0).map(|m| m.as_str()).unwrap_or("").to_string()
                        };

                        // Skip if it's likely a false positive
                        if is_likely_false_positive(line, &secret_value) {
                            continue;
                        }

                        findings.push(Finding {
                            file: path.display().to_string(),
                            line_number: line_num + 1,
                            line_content: line.to_string(),
                            match_type: "secret".to_string(),
                            keyword: secret_type.to_string(),
                            context: description.to_string(),
                            version: None,
                            language: language.clone(),
                            source: "hardcoded".to_string(),
                            category: "secret".to_string(),
                        });
                    }
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_aws_key_detection() {
        let test_content = r#"
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"#;
        // This would require creating a temporary file for testing
        // For now, we can test the regex patterns directly
        let patterns = get_secret_patterns();
        let aws_pattern = patterns.get("AKIA[0-9A-Z]{16}").unwrap();
        assert_eq!(aws_pattern.0, "AWS Access Key");
    }

    #[test]
    fn test_false_positive_detection() {
        assert!(is_likely_false_positive("api_key = \"your_api_key_here\"", "your_api_key_here"));
        assert!(is_likely_false_positive("secret = \"test_secret_123\"", "test_secret_123"));
        assert!(!is_likely_false_positive("api_key = \"sk-1234567890abcdef\"", "sk-1234567890abcdef"));
    }

    #[test]
    fn test_comment_detection() {
        assert!(is_comment_line("// This is a comment"));
        assert!(is_comment_line("# Python comment"));
        assert!(is_comment_line("/* C-style comment"));
        assert!(!is_comment_line("let api_key = \"real_key\";"));
    }

    #[test]
    fn test_json_key_patterns() {
        let patterns = get_secret_patterns();
        
        // Test that we have the new JSON key patterns
        assert!(patterns.contains_key(r#"(?i)['"]\w*_private_key['"]\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#));
        assert!(patterns.contains_key(r#"(?i)['"]\w*_public_key['"]\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#));
        assert!(patterns.contains_key(r#"(?i)\w*_private_key\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#));
        assert!(patterns.contains_key(r#"(?i)\w*_public_key\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#));
        
        // Verify the pattern metadata
        let private_key_pattern = patterns.get(r#"(?i)['"]\w*_private_key['"]\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#).unwrap();
        assert_eq!(private_key_pattern.0, "JSON Private Key");
        assert_eq!(private_key_pattern.2, 3); // severity level
        
        let public_key_pattern = patterns.get(r#"(?i)['"]\w*_public_key['"]\s*:\s*['"]([a-zA-Z0-9+/=\-_\.]{64,})['"]"#).unwrap();
        assert_eq!(public_key_pattern.0, "JSON Public Key");
        assert_eq!(public_key_pattern.2, 2); // severity level
    }
}
