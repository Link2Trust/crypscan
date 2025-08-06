use crate::utils::file_utils::read_file_to_string;
use crate::utils::report::Finding;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

/// Map of match-pattern -> (label, source, language, optional version)
fn get_crypto_keywords() -> HashMap<&'static str, (&'static str, &'static str, &'static str, Option<&'static str>)> {
    let mut map = HashMap::new();

    // Rust
    map.insert("openssl", ("openssl", "use", "Rust", Some("0.10")));
    map.insert("ring", ("ring", "use", "Rust", None));
    map.insert("rustls", ("rustls", "use", "Rust", None));
    map.insert("secrecy", ("secrecy", "use", "Rust", None));

    // Python
    map.insert("cryptography", ("cryptography", "import", "Python", None));
    map.insert("pycrypto", ("pycrypto", "import", "Python", None));
    map.insert("pycryptodome", ("pycryptodome", "import", "Python", None));
    map.insert("ssl", ("ssl", "import", "Python", None));
    map.insert("hashlib", ("hashlib", "import", "Python", None));
    map.insert("jwt", ("jwt", "import", "Python", None));

    // Java
    map.insert("javax.crypto", ("javax.crypto", "import", "Java", None));
    map.insert("bouncycastle", ("bouncycastle", "import", "Java", None));
    map.insert("java.security", ("java.security", "import", "Java", None));
    map.insert("sun.security", ("sun.security", "import", "Java", None));

    // JS / Node
    map.insert("require('crypto')", ("crypto", "require", "JavaScript", None));
    map.insert("require(\"crypto\")", ("crypto", "require", "JavaScript", None));
    map.insert("require('jsonwebtoken')", ("jsonwebtoken", "require", "JavaScript", None));
    map.insert("require(\"jsonwebtoken\")", ("jsonwebtoken", "require", "JavaScript", None));
    map.insert("require('bcrypt')", ("bcrypt", "require", "JavaScript", None));
    map.insert("require(\"argon2\")", ("argon2", "require", "JavaScript", None));
    map.insert("require('node-forge')", ("node-forge", "require", "JavaScript", None));

    // Go
    map.insert("crypto/", ("crypto", "import", "Go", None));
    map.insert("golang.org/x/crypto", ("golang.crypto", "import", "Go", None));

    // C / C++
    map.insert("#include <openssl", ("openssl", "include", "C/C++", None));
    map.insert("#include <sodium.h>", ("libsodium", "include", "C/C++", None));
    map.insert("#include <mbedtls", ("mbedtls", "include", "C/C++", None));
    map.insert("#include <wolfssl", ("wolfssl", "include", "C/C++", None));

    map
}

fn to_safe_regex(pattern: &str) -> Regex {
    if pattern.contains("require(") || pattern.starts_with("#include") || pattern.contains('/') {
        Regex::new(&regex::escape(pattern)).unwrap()
    } else {
        Regex::new(&format!(r"\b{}\b", regex::escape(pattern))).unwrap()
    }
}

/// Scans a source file for crypto-related patterns
pub fn scan_file(path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let keywords = get_crypto_keywords();

    if let Ok(content) = read_file_to_string(path) {
        for (i, line) in content.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with('*') {
                continue;
            }

            for (pattern, (label, source, language, version)) in &keywords {
                let re = to_safe_regex(pattern);
                if re.is_match(line) {
                    findings.push(Finding {
                        file: path.display().to_string(),
                        line_number: i + 1,
                        line_content: line.to_string(),
                        match_type: source.to_string(),
                        keyword: label.to_string(),
                        context: source.to_string(),
                        version: version.map(|v| v.to_string()),
                        language: language.to_string(),
                        source: source.to_string(),
                        category: "library".to_string(), // ✅ new field populated
                    });
                }
            }
        }
    }

    findings
}
