# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Build & Run Commands

```bash
# Build CLI-only
cargo build --release

# Build with web server (recommended)
cargo build --release --features server

# Run web dashboard (development)
cargo run --release --features server -- --serve --port 8081

# Run CLI scan
cargo run --release -- --path /path/to/scan

# With verbose logging
RUST_LOG=info cargo run --release -- --path ./src
```

## Testing

```bash
cargo test                              # All tests
cargo test --lib                        # Unit tests only
cargo test --test integration_tests     # Integration tests only
cargo test test_name -- --nocapture     # Specific test with output
```

## Code Quality

```bash
cargo fmt                    # Format code
cargo clippy --all-features  # Lint with all features
cargo check                  # Fast syntax/type check
```

## Architecture Overview

CryptoScanner discovers cryptographic usage in codebases via parallel scanning with multiple specialized scanner plugins.

### Dual-Mode Execution
- **CLI mode**: Default sync execution for command-line scanning
- **Server mode**: Async web server with REST API (requires `--features server`)
- Conditional compilation via `#[cfg(feature = "server")]` throughout `main.rs` and `lib.rs`

### Scanner Plugin System (`src/scanner/`)
The scanner engine in `mod.rs` coordinates multiple independent scanners that run in parallel via `rayon`:

| Scanner | File | Purpose |
|---------|------|---------|
| Code | `code.rs` | Detects 30+ crypto library imports/usage |
| Secrets | `secrets.rs` | 25+ patterns for hardcoded secrets (AWS keys, tokens, etc.) |
| Artefacts | `artefacts.rs` | Keystore files (.pem, .jks, .p12) and CLI commands |
| Binary | `binary.rs` | Binary file analysis |
| Network | `network.rs` | Network-related scanning |

Each scanner returns `Finding` structs (defined in `utils/report.rs`) with file, line, match type, and category.

### Key Data Flow
1. `config.rs`: CLI args via `clap`, creates `Config` struct
2. `scanner/mod.rs`: `scan_directory()` orchestrates file traversal (`walkdir`) and parallel scanning
3. `utils/file_utils.rs`: MIME detection, file filtering
4. `utils/lang_ident.rs`: Language detection (40+ languages)
5. `utils/report.rs`: JSON output generation
6. `cbom/mod.rs`: CycloneDX CBOM generation

### Web Server (`src/server.rs`)
When `--features server` is enabled:
- `warp` framework serves REST endpoints at `/api/scan/*`
- Background scans tracked via `Arc<Mutex<HashMap>>` shared state
- Static files served from `web/` directory
- Frontend polls `/api/scan/status/{id}` for progress

### Regex Patterns
All scanners use `lazy_static!` for pre-compiled regex patterns. When adding new patterns:
- Add to the appropriate `lazy_static!` block
- Patterns compile once at startup (4-10x faster than runtime compilation)
- Use `(?i)` for case-insensitive matching

### Adding a New Scanner
1. Create `src/scanner/new_scanner.rs`
2. Implement scanning function returning `Vec<Finding>`
3. Add module to `src/scanner/mod.rs`
4. Call from `scan_directory()` in `mod.rs`
5. Add tests in `tests/integration_tests.rs`

## Project-Specific Patterns

### Feature Flags
- `server` feature gates all `tokio`/`warp` dependencies
- Check conditional compilation when editing `main.rs` or `lib.rs`

### File Size Limits
Default 10MB limit in `scanner/mod.rs` prevents memory issues. Configurable via constants.

### Skipped Directories
`scanner/mod.rs` defines `SKIP_DIRS` for `node_modules`, `.git`, `target`, `build`, etc.

### Error Handling
- All scanners use `Result<>` with graceful degradation
- File read errors are logged but don't halt scanning

## REST API Endpoints (Server Mode)

```
POST /api/scan          - Start scan (body: {"location": "...", "timestamp": "..."})
GET  /api/scan/status/{id} - Check scan progress
POST /api/scan/cancel   - Cancel running scan
```
