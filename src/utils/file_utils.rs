use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;

/// Reads the full file content into a string
pub fn read_file_to_string(path: &Path) -> io::Result<String> {
    fs::read_to_string(path)
}

/// Detects the MIME type using the first few bytes of the file
pub fn detect_mime_type(path: &Path) -> Option<String> {
    let mut buf = [0u8; 512];
    let mut file = File::open(path).ok()?;
    let n = file.read(&mut buf).ok()?;
    infer::get(&buf[..n]).map(|kind| kind.mime_type().to_string())
}
