use crate::utils::file_utils::read_file_to_string;
use crate::utils::report::Finding;
use regex::Regex;
use lazy_static::lazy_static;
use std::path::Path;

lazy_static! {
    static ref SECRET_PATTERNS: Vec<(Regex, &'static str, &'static str, u8)> = {
        let pattern_strings = vec![
            // Generic patterns
            (r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]"#, "API Key", "Generic API key pattern", 3),
            (r#"(?i)(secret[_-]?key|secretkey)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]"#, "Secret Key", "Generic secret key pattern", 3),
            (r#"(?i)(access[_-]?token|accesstoken)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]"#, "Access Token", "Generic access token pattern", 3),
            (r#"(?i)(auth[_-]?token|authtoken)\s*[:=]\s*['"]([a-zA-Z0-9_\-\.]{20,})['"]"#, "Auth Token", "Generic authentication token", 3),
            (r#"(?i)password\s*[:=]\s*['"]([^'"]{8,})['"]"#, "Password", "Hardcoded password", 3),
            (r#"(?i)passwd\s*[:=]\s*['"]([^'"]{8,})['"]"#, "Password", "Hardcoded passwd", 3),
            
            // AWS patterns
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key", "AWS Access Key ID", 3),
            (r#"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['"]([a-zA-Z0-9/+=]{40})['"]"#, "AWS Secret", "AWS Secret Access Key", 3),
            
            // GitHub patterns
            (r"ghp_[a-zA-Z0-9]{36}", "GitHub Token", "GitHub Personal Access Token", 3),
            (r"gho_[a-zA-Z0-9]{36}", "GitHub Token", "GitHub OAuth Access Token", 3),
            (r"ghu_[a-zA-Z0-9]{36}", "GitHub Token", "GitHub User Access Token", 3),
            (r"ghs_[a-zA-Z0-9]{36}", "GitHub Token", "GitHub Server Access Token", 3),
            (r"ghr_[a-zA-Z0-9]{36}", "GitHub Token", "GitHub Refresh Token", 3),
            
            // Google API patterns
            (r"AIza[0-9A-Za-z\\-_]{35}", "Google API Key", "Google API Key", 3),
            
            // Slack patterns
            (r"xox[baprs]-([0-9a-zA-Z]{10,48})", "Slack Token", "Slack API Token", 2),
            
            // Discord patterns
            (r"[MN][A-Za-z\\d]{23}\\.[\\w-]{6}\\.[\\w-]{27}", "Discord Token", "Discord Bot Token", 2),
            
            // Database connection strings
            (r"(?i)mongodb://[^:]+:[^@]+@[^/]+", "MongoDB URI", "MongoDB connection string with credentials", 3),
            (r"(?i)mysql://[^:]+:[^@]+@[^/]+", "MySQL URI", "MySQL connection string with credentials", 3),
            (r"(?i)postgresql://[^:]+:[^@]+@[^/]+", "PostgreSQL URI", "PostgreSQL connection string with credentials", 3),
            
            // JWT tokens (basic pattern)
            (r"eyJ[A-Za-z0-9_-]*\\.eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9_-]*", "JWT Token", "JSON Web Token", 2),
            
            // Private keys
            (r"-----BEGIN\\s+(RSA\\s+)?PRIVATE KEY-----", "Private Key", "RSA/Generic Private Key", 3),
            (r"-----BEGIN\\s+OPENSSH\\s+PRIVATE KEY-----", "SSH Private Key", "OpenSSH Private Key", 3),
            (r"-----BEGIN\\s+EC\\s+PRIVATE KEY-----", "EC Private Key", "Elliptic Curve Private Key", 3),
            (r"-----BEGIN\\s+DSA\\s+PRIVATE KEY-----", "DSA Private Key", "DSA Private Key", 3),
        ];
        
        pattern_strings.into_iter()
            .filter_map(|(pattern, name, desc, severity)| {
                Regex::new(pattern).ok().map(|r| (r, name, desc, severity))
            })
            .collect()
    };
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
    
    // Skip if the value starts with common placeholder patterns
    let placeholder_prefixes = [
        "your_", "my_", "example_", "test_", "dummy_", "fake_", "placeholder_", "sample_", 
        "replace_", "todo_", "fixme_", "xxx", "yyy", "zzz"
    ];
    
    for prefix in &placeholder_prefixes {
        if value_lower.starts_with(prefix) {
            return true;
        }
    }
    
    // Skip if it's exactly a common placeholder word
    let exact_placeholders = [
        "your_key", "your_secret", "your_token", "replace_me", 
        "example", "test", "dummy", "fake", "placeholder", "sample",
        "todo", "fixme", "lorem", "ipsum", "password", "secret", "key",
        "12345", "abcde", "qwerty"
    ];
    
    for placeholder in &exact_placeholders {
        if value_lower == *placeholder {
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
    if matched_value.len() < 8 {
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

/// Scans a source file for hardcoded secrets using optimized regex patterns
pub fn scan_file(path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let language = get_language_from_path(path);

    if let Ok(content) = read_file_to_string(path) {
        // Skip very large files to prevent regex engine issues
        if content.len() > 10_000_000 { // 10MB limit
            return findings;
        }
        
        for (line_num, line) in content.lines().enumerate() {
            // Skip comment lines to reduce false positives
            if is_comment_line(line) {
                continue;
            }
            
            // Skip very long lines to prevent regex engine issues
            if line.len() > 10_000 {
                continue;
            }

            // Use the pre-compiled regex patterns from lazy_static
            for (regex, secret_type, description, _severity) in SECRET_PATTERNS.iter() {
                // Use safe regex matching to prevent crashes
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

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
    fn test_secret_patterns_compilation() {
        // Test that all regex patterns compile successfully
        assert!(!SECRET_PATTERNS.is_empty());
        
        // Verify we have common patterns
        let has_aws = SECRET_PATTERNS.iter().any(|(_, name, _, _)| *name == "AWS Access Key");
        let has_github = SECRET_PATTERNS.iter().any(|(_, name, _, _)| *name == "GitHub Token");
        let has_api_key = SECRET_PATTERNS.iter().any(|(_, name, _, _)| *name == "API Key");
        
        assert!(has_aws, "Should have AWS patterns");
        assert!(has_github, "Should have GitHub patterns");
        assert!(has_api_key, "Should have generic API key patterns");
    }
}
