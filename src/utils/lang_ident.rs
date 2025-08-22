use std::path::Path;

/// Enhanced language detection based on file extension and filename patterns
pub fn detect_language(path: &Path) -> String {
    // First check by extension
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext = ext.to_lowercase();
        let language = match ext.as_str() {
            "rs" => "Rust",
            "py" | "pyw" | "pyi" => "Python",
            "java" | "class" => "Java",
            "js" | "mjs" | "cjs" => "JavaScript",
            "ts" | "tsx" => "TypeScript",
            "jsx" => "JSX",
            "cpp" | "cc" | "cxx" | "c++" | "hpp" | "hxx" | "hh" => "C++",
            "c" | "h" => "C",
            "cs" => "C#",
            "go" => "Go",
            "php" | "php3" | "php4" | "php5" | "phtml" => "PHP",
            "rb" | "rbw" => "Ruby",
            "kt" | "kts" => "Kotlin",
            "swift" => "Swift",
            "scala" | "sc" => "Scala",
            "pl" | "pm" | "t" => "Perl",
            "sh" | "bash" | "zsh" | "fish" => "Shell",
            "ps1" | "psm1" | "psd1" => "PowerShell",
            "cmd" | "bat" => "Batch",
            "yaml" | "yml" => "YAML",
            "json" => "JSON",
            "toml" => "TOML",
            "xml" | "xsd" | "xsl" => "XML",
            "html" | "htm" => "HTML",
            "css" | "scss" | "sass" | "less" => "CSS",
            "sql" => "SQL",
            "dockerfile" => "Dockerfile",
            "env" => "Environment",
            "ini" | "cfg" | "conf" | "config" => "Configuration",
            "md" | "markdown" => "Markdown",
            "tex" => "LaTeX",
            "r" => "R",
            "m" => "Objective-C",
            "mm" => "Objective-C++",
            "dart" => "Dart",
            "lua" => "Lua",
            "vim" => "Vim Script",
            "asm" | "s" => "Assembly",
            _ => "Unknown"
        };
        return language.to_string();
    }
    
    // Check by filename patterns if no extension
    if let Some(filename) = path.file_name().and_then(|f| f.to_str()) {
        let filename_lower = filename.to_lowercase();
        match filename_lower.as_str() {
            "dockerfile" | "dockerfile.dev" | "dockerfile.prod" => return "Dockerfile".to_string(),
            "makefile" | "gnumakefile" => return "Makefile".to_string(),
            "rakefile" => return "Ruby".to_string(),
            "gemfile" | "gemfile.lock" => return "Ruby".to_string(),
            "package.json" | "package-lock.json" => return "JSON".to_string(),
            "cargo.toml" | "cargo.lock" => return "TOML".to_string(),
            "go.mod" | "go.sum" => return "Go Module".to_string(),
            "requirements.txt" | "setup.py" | "pyproject.toml" => return "Python".to_string(),
            "pom.xml" | "build.gradle" => return "Build Script".to_string(),
            ".env" | ".env.local" | ".env.development" | ".env.production" | ".env.test" => return "Environment".to_string(),
            _ => {}
        }
    }
    
    "Unknown".to_string()
}

/// Check if a file is likely a configuration file
pub fn is_configuration_file(path: &Path) -> bool {
    let language = detect_language(path);
    matches!(language.as_str(), "YAML" | "JSON" | "TOML" | "XML" | "Environment" | "Configuration")
}

/// Check if a file is likely a source code file
pub fn is_source_code_file(path: &Path) -> bool {
    let language = detect_language(path);
    !matches!(language.as_str(), "Unknown" | "Markdown" | "Configuration" | "Environment" | "CSS")
}
