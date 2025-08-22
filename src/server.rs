use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use warp::{Filter, Reply};
use log::{info, error};

use crate::config::Config;
use crate::scanner::scan_directory;

// Scan request structure
#[derive(Deserialize, Debug)]
struct ScanRequest {
    location: String,
    timestamp: String,
}

// Scan response structure
#[derive(Serialize, Debug)]
struct ScanResponse {
    scan_id: String,
    status: String,
    message: String,
}

// Scan status structure
#[derive(Debug, Clone)]
struct ScanStatus {
    status: String, // "running", "completed", "failed"
    progress: Option<String>,
    error: Option<String>,
    started_at: Instant,
    completed_at: Option<Instant>,
}

// Serializable version for API responses
#[derive(Serialize, Debug)]
struct ScanStatusResponse {
    status: String,
    progress: Option<String>,
    error: Option<String>,
}

// Global scan tracking
type ScanTracker = Arc<Mutex<HashMap<String, ScanStatus>>>;

pub async fn start_server(port: u16, web_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting CryptoScanner web server on port {}", port);
    
    // Initialize scan tracker
    let scan_tracker: ScanTracker = Arc::new(Mutex::new(HashMap::new()));
    
    // Static files route
    let static_files = warp::fs::dir(web_dir.clone());
    
    // API Routes
    let api = api_routes(scan_tracker.clone());
    
    // Root route - serve index.html
    let root = warp::path::end()
        .and(warp::fs::file(web_dir.join("index.html")));
    
    // Combine all routes
    let routes = root
        .or(api)
        .or(static_files)
        .with(warp::cors().allow_any_origin());
    
    info!("Server ready at http://localhost:{}", port);
    info!("Dashboard available at http://localhost:{}/", port);
    
    warp::serve(routes)
        .run(([127, 0, 0, 1], port))
        .await;
    
    Ok(())
}

fn api_routes(scan_tracker: ScanTracker) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    let scan_route = warp::path("api")
        .and(warp::path("scan"))
        .and(warp::path::end())
        .and(warp::post())
        .and(warp::body::json())
        .and(with_scan_tracker(scan_tracker.clone()))
        .and_then(initiate_scan_handler);
    
    let status_route = warp::path("api")
        .and(warp::path("scan"))
        .and(warp::path("status"))
        .and(warp::path::param::<String>())
        .and(warp::path::end())
        .and(warp::get())
        .and(with_scan_tracker(scan_tracker.clone()))
        .and_then(scan_status_handler);
    
    let cancel_route = warp::path("api")
        .and(warp::path("scan"))
        .and(warp::path("cancel"))
        .and(warp::path::end())
        .and(warp::post())
        .and(with_scan_tracker(scan_tracker.clone()))
        .and_then(cancel_scan_handler);
    
    scan_route.or(status_route).or(cancel_route)
}

fn with_scan_tracker(tracker: ScanTracker) -> impl Filter<Extract = (ScanTracker,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || tracker.clone())
}

async fn initiate_scan_handler(
    request: ScanRequest,
    tracker: ScanTracker,
) -> Result<impl warp::Reply, warp::Rejection> {
    info!("Received scan request for location: {}", request.location);
    
    // Validate scan location
    if !is_valid_scan_location(&request.location) {
        let error_response = ScanResponse {
            scan_id: "".to_string(),
            status: "error".to_string(),
            message: "Invalid scan location. Please provide a valid local path or repository URL.".to_string(),
        };
        return Ok(warp::reply::with_status(
            warp::reply::json(&error_response),
            warp::http::StatusCode::BAD_REQUEST,
        ));
    }
    
    // Generate unique scan ID
    let scan_id = Uuid::new_v4().to_string();
    
    // Initialize scan status
    let status = ScanStatus {
        status: "running".to_string(),
        progress: Some("Preparing scan...".to_string()),
        error: None,
        started_at: Instant::now(),
        completed_at: None,
    };
    
    // Store scan status
    {
        let mut tracker = tracker.lock().unwrap();
        tracker.insert(scan_id.clone(), status);
    }
    
    // Start scan in background thread
    let scan_id_clone = scan_id.clone();
    let location = request.location.clone();
    let tracker_clone = tracker.clone();
    
    thread::spawn(move || {
        execute_scan(scan_id_clone, location, tracker_clone);
    });
    
    // Return immediate response
    let response = ScanResponse {
        scan_id: scan_id.clone(),
        status: "initiated".to_string(),
        message: format!("Scan initiated for location: {}", request.location),
    };
    
    Ok(warp::reply::with_status(
        warp::reply::json(&response),
        warp::http::StatusCode::ACCEPTED,
    ))
}

async fn scan_status_handler(
    scan_id: String,
    tracker: ScanTracker,
) -> Result<impl warp::Reply, warp::Rejection> {
    let tracker = tracker.lock().unwrap();
    
    match tracker.get(&scan_id) {
        Some(status) => {
            let response = ScanStatusResponse {
                status: status.status.clone(),
                progress: status.progress.clone(),
                error: status.error.clone(),
            };
            Ok(warp::reply::with_status(
                warp::reply::json(&response),
                warp::http::StatusCode::OK,
            ))
        }
        None => {
            let error_response = serde_json::json!({
                "status": "not_found",
                "error": "Scan ID not found"
            });
            Ok(warp::reply::with_status(
                warp::reply::json(&error_response),
                warp::http::StatusCode::NOT_FOUND,
            ))
        }
    }
}

async fn cancel_scan_handler(
    _tracker: ScanTracker,
) -> Result<impl warp::Reply, warp::Rejection> {
    // For simplicity, we'll just acknowledge the cancel request
    // In a more sophisticated implementation, you'd track and actually cancel running scans
    info!("Scan cancellation requested");
    
    let response = serde_json::json!({
        "status": "cancelled",
        "message": "Scan cancellation requested"
    });
    
    Ok(warp::reply::with_status(
        warp::reply::json(&response),
        warp::http::StatusCode::OK,
    ))
}

fn execute_scan(scan_id: String, location: String, tracker: ScanTracker) {
    info!("Starting scan execution for ID: {} at location: {}", scan_id, location);
    
    // Update status to indicate scan is processing
    update_scan_status(&tracker, &scan_id, "running", Some("Processing scan location..."), None);
    
    // Create config for the scan
    let mut config = Config {
        path: location.clone(),
        use_mime_filter: false,
        skip_secrets: false,
        serve: false,
        port: 8080,
        web_dir: "./web".to_string(),
    };
    
    // Handle different location types
    let scan_path = if is_repository_url(&location) {
        // For repository URLs, we'd typically clone them first
        // For now, we'll just simulate this
        update_scan_status(&tracker, &scan_id, "running", Some("Cloning repository..."), None);
        
        // TODO: Implement actual repository cloning
        // For now, return error since we haven't implemented git cloning yet
        update_scan_status(&tracker, &scan_id, "failed", None, Some("Repository scanning not implemented yet. Please use local paths.".to_string()));
        return;
    } else {
        // Local path
        if !Path::new(&location).exists() {
            let error_msg = format!("Path does not exist: {}", location);
            update_scan_status(&tracker, &scan_id, "failed", None, Some(error_msg));
            return;
        }
        location.clone()
    };
    
    config.path = scan_path;
    
    // Update status
    update_scan_status(&tracker, &scan_id, "running", Some("Scanning files..."), None);
    
    // Execute the actual scan
    match scan_directory(&config) {
        Ok(()) => {
            info!("Scan {} completed successfully", scan_id);
            update_scan_status(&tracker, &scan_id, "completed", Some("Scan completed successfully"), None);
        }
        Err(e) => {
            error!("Scan {} failed: {}", scan_id, e);
            let error_msg = format!("Scan failed: {}", e);
            update_scan_status(&tracker, &scan_id, "failed", None, Some(error_msg));
        }
    }
}

fn update_scan_status(
    tracker: &ScanTracker,
    scan_id: &str,
    status: &str,
    progress: Option<&str>,
    error: Option<String>,
) {
    let mut tracker = tracker.lock().unwrap();
    if let Some(scan_status) = tracker.get_mut(scan_id) {
        scan_status.status = status.to_string();
        scan_status.progress = progress.map(|s| s.to_string());
        scan_status.error = error;
        
        if status == "completed" || status == "failed" {
            scan_status.completed_at = Some(Instant::now());
        }
    }
}

fn is_valid_scan_location(location: &str) -> bool {
    is_local_path(location) || is_repository_url(location)
}

fn is_local_path(location: &str) -> bool {
    // Check for absolute paths, relative paths, or home directory paths
    location.starts_with('/') || 
    location.starts_with("./") || 
    location.starts_with("../") || 
    location.starts_with("~/") ||
    (location.len() > 2 && location.chars().nth(1) == Some(':')) // Windows drive letters
}

fn is_repository_url(location: &str) -> bool {
    location.starts_with("https://") || 
    location.starts_with("http://") || 
    location.starts_with("git@") || 
    location.starts_with("ssh://")
}

// Utility function to serve static files with proper MIME types
pub fn serve_static_file<P: AsRef<Path>>(path: P) -> Result<impl Reply, io::Error> {
    let path = path.as_ref();
    let content = fs::read(path)?;
    
    let mime_type = match path.extension().and_then(|ext| ext.to_str()) {
        Some("html") => "text/html",
        Some("css") => "text/css",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    };
    
    Ok(warp::reply::with_header(
        warp::reply::with_header(
            content,
            "content-type",
            mime_type,
        ),
        "cache-control",
        "public, max-age=3600",
    ))
}
