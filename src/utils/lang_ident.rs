use std::path::Path;

/// Guess the programming language based on file extension
pub fn detect_language(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("rs") => "Rust",
        Some("py") => "Python",
        Some("java") => "Java",
        Some("js") => "JavaScript",
        Some("ts") => "TypeScript",
        Some("cpp") | Some("cc") | Some("cxx") | Some("c++") => "C++",
        Some("c") => "C",
        Some("cs") => "C#",
        Some("go") => "Go",
        Some("php") => "PHP",
        Some("html") | Some("xml") | Some("json") => "Markup",
        _ => "Unknown",
    }
    .to_string()
}
