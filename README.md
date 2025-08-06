# 🔐 CryptoScanner

![Rust](https://img.shields.io/badge/Rust-2021-orange)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License: MIT](https://img.shields.io/badge/license-MIT-blue)

A high-performance Rust tool to **discover cryptographic usage** across your codebase and infrastructure.  
CryptoScanner detects **libraries, keystore files, and key management activity**, and presents results in an interactive web dashboard.

---

## ✨ Features

- 🧠 **Detects cryptographic libraries** (e.g. `openssl`, `crypto`, `ring`, `bouncycastle`)
- 🗂️ **Finds keystore artefacts** by file extension (`.pem`, `.jks`, `.p12`, etc.)
- 💻 **Scans for key management commands** in scripts (e.g. `openssl genpkey`, `gpg --import`)
- ⚡ **Parallel scanning** with `rayon`
- 🧠 Optional **MIME-based filtering** (`--use-mime-filter`)
- 📁 Skips known non-code folders and files (`node_modules`, `.css`, `build`, etc.)
- 📊 Outputs structured findings in JSON
- 🌐 **Visual dashboard** with charts for:
  - Libraries (bar/pie)
  - File types
  - Separate table for artefacts (non-library findings)
- 🎨 Color-synced pie and bar charts with data labels

---


## 🚀 Installation

### Prerequisites

- ✅ [Rust](https://www.rust-lang.org/tools/install) (stable)
- ✅ Python 3 (to serve the dashboard locally)
- ✅ Visual Studio Code (for clickable links via `vscode://`)

### Clone the repository

```bash
git clone https://github.com/Link2Trust/crypsca.git
cd crypscan
```

### Build the scanner

```bash
cargo build --release
```

---

## 🧪 Usage

### Run the scanner on a folder

```bash
cargo run --release -- --path /path/to/codebase
```
---

This command will:
- Recursively scan all files in the specified folder
- Detect crypto-related keywords (e.g., `openssl`, `sha256`, `bouncycastle`)
- Ignore commented lines
- Output a structured file to `output/findings.json`

### With MIME filtering

```bash
cargo run --release -- --path ./my_project --use-mime-filter
```
- Enable MIME-type detection to skip e.g. logs, docs

### Example output (JSON)

```json
[
  {
    "file": "User/project/src/CryptoService.java",
    "line_number": 24,
    "line_content": "import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;",
    "match_type": "import",
    "keyword": "bouncycastle",
    "context": "import",
    "version": null,
    "language": "Java",
    "source": "import",
    "category": "library"
  }
]
```

---

## 📊 Dashboard

A dashboard is included to visualize the findings.

### Serve it locally

```bash
cd web
python3 -m http.server
```

Then open your browser at:  
➡️ [http://localhost:8000](http://localhost:8000)

### Dashboard features

- 📊 **Bar and pie charts** showing:
  - Library usage (grouped by version)
  - File types (.js, .py, .rs, etc.)
  - Cryptographic Artifacts found (.p12, pem, jks, etc.)
- 🖱️ **Double-click a chart item** to view details
- 🧩 **Details page** shows:
  - File, line number, context, and code snippet
  - **Clickable file paths** that open in VS Code via `vscode://` protocol

### Example Dashboard

<img width="825" height="1076" alt="image" src="https://github.com/user-attachments/assets/83f371ae-4309-4bb6-a61f-7bf3f85c2964" />


### Example Details page

<img width="1900" height="494" alt="image" src="https://github.com/user-attachments/assets/c48d5f35-85de-4a36-b9b0-4059086ee5ea" />


---

## 📂 File Structure

```bash
crypto-scanner/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── config.rs            # Config & CLI flags
│   ├── scanner/
│   │   ├── mod.rs
│   │   ├── code.rs          # Library usage scanner
│   │   ├── artefacts.rs     # Keystore + CLI command discovery
│   └── utils/
│       ├── file_utils.rs
│       ├── report.rs
├── output/                  # Optional export dir
├── web/
│   ├── index.html           # Dashboard entry
│   ├── dashboard.js         # Chart.js logic
│   ├── details.html         # Filtered VS Code links
│   └── data/findings.json   # Scanner output
├── Cargo.toml
└── README.md
```
---

## 📦 Dependencies

| Dependency         | Purpose                              |
|--------------------|--------------------------------------|
| `walkdir`          | Recursive directory traversal        |
| `regex`            | Pattern matching and version parsing |
| `serde`            | JSON serialization of results        |
| `clap`             | CLI argument parsing                 |
| `Chart.js`         | Frontend visualization (dashboard)   |
| `ChartDataLabels`  | Bar and pie chart labels             |
| `rayon`            | Parallel scanning                    |
| `infer`            | MIME detection                       |
| `indicatif`        | Progress bar for scanning            |
---

## ✅ TODO / Roadmap

- [ ] Support multi-line crypto expression parsing
- [ ] Add support for secrets (e.g. hardcoded keys)
- [ ] WASM-based scanner integration
- [ ] Remote scanning via SSH

---

## 🛟 Support & Contributions

PRs welcome!  
For suggestions or issues, open a [GitHub Issue](https://github.com/Link2Trust/crypto-scanner/issues).

---

## 📄 License

MIT License © 2025 Link2Trust
