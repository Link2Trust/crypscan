# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Common Development Commands

### Building the Project

```bash
# Build CLI-only version
cargo build --release

# Build with web server support (recommended)
cargo build --release --features server

# Development build (faster compilation)
cargo build
```

### Running CryptoScanner

```bash
# Run web dashboard mode (recommended for development)
cargo run --release --features server -- --serve --port 8081

# Run CLI scan on current directory
cargo run --release

# Run CLI scan on specific directory
cargo run --release -- --path /path/to/scan

# Run with verbose logging
RUST_LOG=info cargo run --release -- --path ./my_project

# Run with debug logging (very verbose)
RUST_LOG=debug cargo run --release -- --path ./src

# Performance optimized scanning for large codebases
cargo run --release -- --path ./large_project --use-mime-filter

# Skip secrets for faster library-only scanning
cargo run --release -- --path ./src --skip-secrets
```

### Development Performance

```bash
# Fast development builds (incremental compilation)
cargo build

# Check build without artifacts (fastest)
cargo check

# Watch mode for development
cargo watch -x check

# Profile release build performance
cargo build --release --timings
```

### Testing

```bash
# Run all tests
cargo test

# Run unit tests only
cargo test --lib

# Run integration tests only
cargo test --test integration_tests

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_function_name

# Run tests with specific patterns
cargo test scanner

# Test performance and memory usage
cargo test --release -- --nocapture
```

### Code Quality

```bash
# Format code
cargo fmt

# Check code with clippy
cargo clippy

# Check all features and combinations
cargo clippy --all-features

# Build documentation
cargo doc --open
```

### CBOM Generation

```bash
# Generate JSON CBOM (default)
cargo run --release -- --path ./src --cbom --app-name "MyApp"

# Generate XML CBOM
cargo run --release -- --path ./src --cbom --cbom-format xml --cbom-output ./cbom.xml --app-name "MyApp"

# Custom CBOM output location
cargo run --release -- --path ./src --cbom --cbom-output ./reports/crypto-analysis.json
```

## High-Level Architecture

CryptoScanner is a high-performance Rust tool for discovering cryptographic usage across codebases. It follows a modular architecture with clear separation of concerns:

### Core Architecture Patterns

- **Parallel Processing**: Uses `rayon` for multi-threaded file scanning
- **Feature Gates**: Web server functionality is behind the `server` feature flag
- **Plugin-Based Scanners**: Multiple specialized scanners work together
- **REST API**: Web server provides RESTful endpoints for scan management

### Main Components

#### Entry Points (`main.rs`)
- **Dual Mode Support**: Automatically switches between CLI and server mode based on feature compilation
- **Async/Sync Coordination**: Uses conditional compilation for async server vs sync CLI
- **CBOM Integration**: Generates CycloneDX Cryptography Bill of Materials

#### Configuration System (`config.rs`)
- **CLI Argument Parsing**: Uses `clap` for comprehensive argument handling  
- **Mode Detection**: Single config struct supports both CLI and server modes
- **Feature Toggles**: Supports MIME filtering, secret scanning toggles

#### Scanner Engine (`scanner/mod.rs`)
The scanner system is plugin-based with multiple specialized scanners:

- **`code.rs`**: Detects 30+ cryptographic libraries in source code
- **`secrets.rs`**: Advanced hardcoded secrets detection (25+ patterns)
- **`artefacts.rs`**: Finds keystore files and key management commands
- **`binary.rs`**: Handles binary file analysis
- **`network.rs`**: Network-related scanning capabilities

#### Web Server (`server.rs`)
- **Background Scan Management**: Tracks multiple concurrent scans with unique IDs
- **Real-time Progress**: WebSocket-like status updates via REST endpoints
- **Static File Serving**: Serves dashboard assets and scan results

#### Utilities (`utils/`)
- **`file_utils.rs`**: MIME detection and file handling
- **`report.rs`**: JSON report generation and finding structures
- **`lang_ident.rs`**: Programming language detection (40+ languages)

#### CBOM Generation (`cbom/`)
- **CycloneDX Compliance**: Generates standard CBOM documents
- **Risk Assessment**: Includes cryptographic risk analysis
- **Multiple Formats**: Supports JSON and XML export

### Key Design Decisions

1. **Performance-First**: Pre-compiled regex patterns with `lazy_static` and parallel processing
2. **False Positive Reduction**: Context-aware filtering and comment detection
3. **Dual Interface**: Single codebase supports both CLI and web interfaces via feature flags
4. **Modular Scanning**: Each scanner type is independent and can be toggled
5. **Standards Compliance**: Generates CycloneDX CBOM for compliance workflows
6. **Memory Safety**: Streaming approach for large codebases to prevent memory issues
7. **Error Resilience**: Graceful degradation when encountering problematic files

### File Processing Pipeline

1. **Directory Traversal**: `walkdir` recursively scans directories
2. **File Filtering**: MIME detection and extension-based filtering
3. **Parallel Scanning**: Multiple scanners process files concurrently
4. **Result Aggregation**: Findings are collected and deduplicated
5. **Report Generation**: Results exported to JSON and optionally CBOM

### Web Dashboard Flow

1. **Scan Initiation**: User submits scan request via web interface
2. **Background Processing**: Server spawns thread for scan execution
3. **Status Tracking**: Scan progress stored in shared state
4. **Real-time Updates**: Frontend polls for status updates
5. **Result Visualization**: Interactive charts and tables display findings

## Project Structure

```
src/
├── main.rs              # Entry point with CLI/server mode switching
├── lib.rs               # Module exports and feature gates
├── config.rs            # CLI argument parsing and configuration
├── server.rs            # Web server with REST API endpoints
├── scanner/             # Core scanning engine
│   ├── mod.rs          # Scanner coordination and file filtering
│   ├── code.rs         # Cryptographic library detection
│   ├── secrets.rs      # Hardcoded secrets scanning
│   ├── artefacts.rs    # Keystore files and commands
│   ├── binary.rs       # Binary file analysis
│   └── network.rs      # Network-related scanning
├── utils/              # Shared utilities
│   ├── file_utils.rs   # File handling and MIME detection
│   ├── report.rs       # JSON report generation
│   ├── lang_ident.rs   # Programming language detection
│   └── mod.rs          # Module coordination
└── cbom/               # CBOM generation system
    └── mod.rs          # CycloneDX document generation

web/                     # Frontend dashboard assets
├── index.html          # Main dashboard interface
├── css/styles.css      # Professional styling
└── js/                 # Interactive functionality
    ├── dashboard.js    # Scan management and charts
    └── theme.js        # Dark/light theme support

tests/
└── integration_tests.rs # End-to-end testing scenarios
```

## Development Notes

### Performance Considerations
- **Pre-compiled Regex**: Uses `lazy_static` to compile patterns once at startup (4-10x faster)
- **Multi-Threading**: Scanners use `rayon::par_iter()` for parallel processing
- **Memory Management**: File size limits (default 10MB) prevent memory exhaustion
- **Streaming Processing**: Large result sets use incremental writes to avoid memory spikes

### Architecture Patterns
- **Error Handling**: Uses `Result<>` types throughout with proper error propagation
- **Feature Gates**: Web server requires `--features server` for compilation
- **Async/Sync Coordination**: Conditional compilation for server vs CLI modes
- **Modular Design**: Scanner plugins can be independently enabled/disabled

### Development Workflow
- **Logging**: Structured logging with `log` crate, configurable via `RUST_LOG`
- **MIME Detection**: Optional MIME filtering to skip binary/log files
- **Progress Tracking**: Visual progress bars in CLI mode, real-time updates in web mode
- **Configuration**: CLI arguments handle both scanning and server configuration

### Common Issues
- **Large Codebases**: Use `--use-mime-filter` to skip non-code files
- **Memory Usage**: For 100K+ files, consider scanning in smaller chunks
- **False Positives**: Comment detection and context filtering reduce noise
- **Build Time**: Use `cargo check` for fast iteration, `cargo clippy` for quality

## Testing Strategy

- **Unit Tests**: Individual scanner functionality and utility functions
- **Integration Tests**: End-to-end scanning with temporary test files
- **Performance Tests**: Large file handling and memory usage validation
- **Safety Tests**: Regex edge cases and malformed input handling
