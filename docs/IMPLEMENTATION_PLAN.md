# PST WEEE Rust Implementation Plan

## Overview

This document provides a detailed, phase-by-phase implementation plan for migrating
PST WEEE from Go to Rust. The plan is designed for incremental delivery with testable
milestones at each phase.

**Estimated Total Duration**: 4-6 weeks
**Risk Level**: Medium (well-understood domain, proven Rust libraries)

### Input/Output Requirements

**Input**: The tool accepts either:

- A **single PST file** path, or
- A **folder path** containing one or more PST files

**Output**: The final deliverable produces a **single, unified, deduplicated CSV file**
containing all extracted contacts from all processed PST files. Deduplication is performed
by email address (case-insensitive), retaining the first display name encountered for
each unique email.

---

## Phase 0: Project Setup & Validation (Days 1-2)

### Objectives

- Establish Rust project structure
- Validate `outlook-pst-rs` compatibility with target PST files
- Set up development environment and CI

### Tasks

#### 0.1 Create Project Scaffold

```bash
cargo new pst_weee_rs
cd pst_weee_rs
```

#### 0.2 Configure Cargo.toml

```toml
[package]
name = "pst_weee"
version = "0.2.0"
edition = "2021"
authors = ["Nick Campbell"]
description = "High-performance email contact extractor for Microsoft Outlook PST files"
license = "MIT"
repository = "https://github.com/greysquirr3l/pst_weee"

[dependencies]
outlook-pst = "1.1"
clap = { version = "4", features = ["derive"] }
csv = "1.3"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
log = "0.4"
env_logger = "0.10"
thiserror = "1"
anyhow = "1"

[dev-dependencies]
tempfile = "3"
```

#### 0.3 Create Proof-of-Concept

```rust
// src/main.rs - Validation POC
use outlook_pst::open_store;
use std::path::Path;

fn main() -> anyhow::Result<()> {
    let pst_path = std::env::args().nth(1)
        .expect("Usage: pst_weee <path-to-pst>");

    let store = open_store(Path::new(&pst_path))?;
    println!("✓ PST opened successfully");

    let props = store.properties();
    println!("Store: {}", props.display_name()?);

    Ok(())
}
```

#### 0.4 Validation Checklist

- [ ] Successfully open sample PST files (Unicode & ANSI formats)
- [ ] Navigate folder hierarchy
- [ ] Access message recipient tables
- [ ] Extract email addresses and display names
- [ ] Verify cross-platform compilation (macOS, Linux, Windows)

### Deliverables

- Working Rust project with `outlook-pst` dependency
- POC that opens and reads a PST file
- Documented any compatibility issues

---

## Phase 1: Core PST Extraction (Days 3-7)

### Objectives

- Implement native PST contact extraction
- Match Go implementation's extraction logic
- Create comprehensive email validation

### Tasks

#### 1.1 Create Module Structure

```
src/
├── main.rs
├── lib.rs
├── error.rs
├── pst/
│   ├── mod.rs
│   ├── extractor.rs
│   └── recipient.rs
└── filter/
    ├── mod.rs
    └── email.rs
```

#### 1.2 Implement Error Types

```rust
// src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PstWeeeError {
    #[error("PST error: {0}")]
    Pst(#[from] std::io::Error),

    #[error("Invalid email format: {0}")]
    InvalidEmail(String),

    #[error("Path error: {0}")]
    PathError(String),
}

pub type Result<T> = std::result::Result<T, PstWeeeError>;
```

#### 1.3 Implement Contact Structure

```rust
// src/pst/mod.rs
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Contact {
    pub email: String,
    pub display_name: Option<String>,
}
```

#### 1.4 Implement PST Extractor

```rust
// src/pst/extractor.rs
use outlook_pst::{
    open_store,
    messaging::{store::Store, folder::Folder, message::Message},
    ltp::prop_context::PropertyValue,
};

pub struct PstExtractor {
    debug_mode: bool,
    max_username_length: usize,
}

impl PstExtractor {
    pub fn new(debug_mode: bool, max_username_length: usize) -> Self {
        Self { debug_mode, max_username_length }
    }

    pub fn extract_contacts(&self, pst_path: &Path) -> Result<Vec<Contact>> {
        let store = open_store(pst_path)?;
        let mut contacts = HashMap::new();

        // Start from IPM subtree (main mailbox folders)
        let root_id = store.properties().ipm_sub_tree_entry_id()?;
        let root = store.open_folder(&root_id)?;

        self.traverse_folder(&store, root.as_ref(), &mut contacts)?;

        Ok(contacts.into_values().collect())
    }

    fn traverse_folder(
        &self,
        store: &Rc<dyn Store>,
        folder: &dyn Folder,
        contacts: &mut HashMap<String, Contact>,
    ) -> Result<()> {
        // Process messages
        if let Some(contents) = folder.contents_table() {
            self.process_messages(store, &contents, contacts)?;
        }

        // Recurse into subfolders
        if let Some(hierarchy) = folder.hierarchy_table() {
            for row in hierarchy.rows_matrix() {
                let entry_id = store.properties()
                    .make_entry_id(NodeId::from(u32::from(row.id())))?;
                if let Ok(subfolder) = store.open_folder(&entry_id) {
                    self.traverse_folder(store, subfolder.as_ref(), contacts)?;
                }
            }
        }

        Ok(())
    }
}
```

#### 1.5 Implement Email Validation (Port from Go)

```rust
// src/filter/email.rs
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"(?i)^[A-Za-z0-9][A-Za-z0-9._%+-]*[A-Za-z0-9]@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
    ).unwrap();

    static ref HEX_PATTERN: Regex = Regex::new(r"(?i)^([0-9a-f]{10,}-[0-9a-f-]+)@").unwrap();
    static ref NUMERIC_PREFIX: Regex = Regex::new(r"(?i)^\d{3}-[a-z]{3}-\d{3}\.\d[.\d]+@").unwrap();
    static ref U_PLUS_LONG: Regex = Regex::new(r"(?i)^u\+[a-z0-9]{30,}@").unwrap();
}

const BLACKLISTED_TERMS: &[&str] = &[
    "unsubscribe", "unsub", "abuse", "amazonses", "marketoemail",
    "mktoemail.com", "bounce", "noreply", "donotreply", "optout",
    "businesstrack.com", "mktomail.com", "messaging.squareup.com",
    "dropbox.com", "squarespace-mail.com", "arksf.com",
];

pub fn validate_email(email: &str, max_username_length: usize) -> bool {
    if email.is_empty() {
        return false;
    }

    // Basic pattern check
    if !EMAIL_REGEX.is_match(email) {
        return false;
    }

    // Check for invalid patterns
    if email.contains("..") || email.contains(".@") || email.matches('@').count() != 1 {
        return false;
    }

    // Check username length
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let username = parts[0];
    if username.len() > max_username_length && username.chars().all(|c| c.is_alphanumeric()) {
        return false;
    }

    // Check rejection patterns
    if HEX_PATTERN.is_match(email)
        || NUMERIC_PREFIX.is_match(email)
        || U_PLUS_LONG.is_match(email)
    {
        return false;
    }

    // Check blacklisted terms
    let email_lower = email.to_lowercase();
    for term in BLACKLISTED_TERMS {
        if email_lower.contains(term) {
            return false;
        }
    }

    // Validate domain
    let domain = parts[1];
    if !domain.contains('.') {
        return false;
    }

    // Check TLD
    let tld = domain.rsplit('.').next().unwrap_or("");
    if tld.len() < 2 || tld.len() > 10 || tld.chars().any(|c| c.is_numeric()) {
        return false;
    }

    true
}
```

### Testing Milestone

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(validate_email("user@example.com", 20));
        assert!(validate_email("first.last@company.co.uk", 20));
        assert!(validate_email("test123@domain.org", 20));
    }

    #[test]
    fn test_invalid_emails() {
        assert!(!validate_email("", 20));
        assert!(!validate_email("invalid", 20));
        assert!(!validate_email("no@tld", 20));
        assert!(!validate_email("unsubscribe@example.com", 20));
        assert!(!validate_email("verylongalphanumericusername@example.com", 20));
    }
}
```

### Deliverables

- Complete PST extraction module
- Email validation matching Go implementation
- Unit tests for validation logic
- Integration test with sample PST file

---

## Phase 2: CLI & Configuration (Days 8-10)

### Objectives

- Implement CLI with identical flags to Go version
- Create configuration management
- Add logging infrastructure

### Tasks

#### 2.1 Implement CLI with Clap

```rust
// src/cli/mod.rs
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "pst_weee")]
#[command(author = "Nick Campbell")]
#[command(version = "0.2.0")]
#[command(about = "High-performance email contact extractor for PST files")]
pub struct Args {
    /// Path to a single PST file or folder containing PST files
    #[arg(short, long)]
    pub input: PathBuf,

    /// Path to output CSV file
    #[arg(short, long, default_value = "contacts.csv")]
    pub output: PathBuf,

    /// Maximum CPU usage percentage (0-100)
    #[arg(long, default_value = "70.0")]
    pub cpu: f64,

    /// Maximum memory usage percentage (0-100)
    #[arg(long, default_value = "70.0")]
    pub memory: f64,

    /// Minimum free memory in GB
    #[arg(long, default_value = "2")]
    pub min_free_memory: u64,

    /// Maximum number of worker threads (0 = auto)
    #[arg(short, long, default_value = "0")]
    pub workers: usize,

    /// Skip checking for available disk space
    #[arg(long)]
    pub ignore_space_check: bool,

    /// Enable safe mode with more conservative resource usage
    #[arg(long)]
    pub safe: bool,

    /// Enable debug logging
    #[arg(long)]
    pub debug: bool,

    /// Disable filtering of invalid TLDs
    #[arg(long)]
    pub disable_tld_filter: bool,

    /// Extract attachments when processing PSTs
    #[arg(long)]
    pub extract_attachments: bool,

    /// Size of chunks for processing in MB
    #[arg(long, default_value = "32")]
    pub chunk_size: usize,

    /// Maximum username length for email filtering
    #[arg(long, default_value = "20")]
    pub max_username_length: usize,
}

impl From<Args> for Config {
    fn from(args: Args) -> Self {
        Config {
            input_path: args.input,
            output_path: args.output,
            cpu_limit: args.cpu,
            memory_limit: args.memory,
            min_free_memory_gb: args.min_free_memory,
            max_workers: args.workers,
            ignore_space_check: args.ignore_space_check,
            safe_mode: args.safe,
            debug_mode: args.debug,
            disable_tld_filter: args.disable_tld_filter,
            extract_attachments: args.extract_attachments,
            chunk_size_mb: args.chunk_size,
            max_username_length: args.max_username_length,
        }
    }
}
```

#### 2.2 Implement Main Entry Point

```rust
// src/main.rs
use clap::Parser;
use env_logger::Env;
use log::{info, error};
use std::time::Instant;

mod cli;
mod config;
mod error;
mod filter;
mod pst;

use cli::Args;
use config::Config;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.debug { "debug" } else { "info" };
    env_logger::Builder::from_env(Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();

    info!("PST WEEE - Email Extractor");
    info!("Version: 0.2.0");
    info!("Input: {:?}", args.input);
    info!("Output file: {:?}", args.output);

    let config: Config = args.into();

    // Validate input path (file or folder)
    if !config.input_path.exists() {
        error!("Input path does not exist: {:?}", config.input_path);
        std::process::exit(1);
    }

    // Validate it's either a PST file or a directory
    let is_pst = config.input_path.extension()
        .map(|e| e.eq_ignore_ascii_case("pst"))
        .unwrap_or(false);
    let is_dir = config.input_path.is_dir();

    if !is_pst && !is_dir {
        error!("Input must be a .pst file or a directory containing PST files");
        std::process::exit(1);
    }

    let start = Instant::now();
    info!("Starting processing...");

    // TODO: Phase 3 - Add processor

    let elapsed = start.elapsed();
    info!("Processing completed in {:?}", elapsed);

    Ok(())
}
```

### Deliverables

- Complete CLI matching Go implementation's flags
- Configuration struct with defaults
- Logging infrastructure with debug mode

---

## Phase 3: Output & Progress Tracking (Days 11-14)

### Objectives

- Implement thread-safe CSV writer
- Create progress persistence (JSON format compatible with Go)
- Add TLD filter with download capability

### Tasks

#### 3.1 Implement CSV Writer

The CSV writer produces a **single output file** that accumulates contacts from all
PST files. Deduplication is handled at the processor level using a `DashMap`,
ensuring only unique email addresses are written.

```rust
// src/output/csv.rs
use csv::Writer;
use std::fs::File;
use std::io::BufWriter;
use std::sync::Mutex;
use std::path::Path;

pub struct CsvWriter {
    writer: Mutex<Writer<BufWriter<File>>>,
    record_count: Mutex<u64>,
    debug_mode: bool,
}

impl CsvWriter {
    pub fn new(output_path: &Path, debug_mode: bool) -> Result<Self> {
        // Create parent directory if needed
        if let Some(parent) = output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = File::create(output_path)?;
        let buf = BufWriter::with_capacity(64 * 1024, file);
        let mut writer = Writer::from_writer(buf);

        // Write header
        writer.write_record(&["Email", "DisplayName"])?;
        writer.flush()?;

        Ok(Self {
            writer: Mutex::new(writer),
            record_count: Mutex::new(0),
            debug_mode,
        })
    }

    pub fn write_contact(&self, contact: &Contact) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        writer.write_record(&[
            &contact.email,
            contact.display_name.as_deref().unwrap_or(""),
        ])?;

        *self.record_count.lock().unwrap() += 1;
        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        self.writer.lock().unwrap().flush()?;
        Ok(())
    }

    pub fn record_count(&self) -> u64 {
        *self.record_count.lock().unwrap()
    }
}
```

#### 3.2 Implement Progress Tracking

```rust
// src/progress/mod.rs
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Progress {
    pub completed_files: HashSet<String>,
    pub current_file: Option<String>,
    pub contacts_found: u64,
    pub bytes_read: u64,
    pub profile_name: Option<String>,
    #[serde(default)]
    pub config_options: HashMap<String, serde_json::Value>,
}

pub struct ProgressTracker {
    progress: Mutex<Progress>,
    save_path: PathBuf,
}

impl ProgressTracker {
    pub fn load_or_create(save_path: impl AsRef<Path>) -> Self {
        let save_path = save_path.as_ref().to_path_buf();

        let progress = if save_path.exists() {
            fs::read_to_string(&save_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Progress::default()
        };

        if !progress.completed_files.is_empty() {
            log::info!("Loaded progress with {} completed files", progress.completed_files.len());
        }

        Self {
            progress: Mutex::new(progress),
            save_path,
        }
    }

    pub fn is_file_completed(&self, filename: &str) -> bool {
        self.progress.lock().unwrap().completed_files.contains(filename)
    }

    pub fn mark_file_complete(&self, filename: &str) -> Result<()> {
        let mut progress = self.progress.lock().unwrap();
        progress.completed_files.insert(filename.to_string());
        progress.current_file = None;
        self.save_locked(&progress)
    }

    pub fn set_current_file(&self, filename: &str) -> Result<()> {
        let mut progress = self.progress.lock().unwrap();
        progress.current_file = Some(filename.to_string());
        self.save_locked(&progress)
    }

    pub fn update_stats(&self, bytes_read: u64, contacts_found: u64) -> Result<()> {
        let mut progress = self.progress.lock().unwrap();
        progress.bytes_read = bytes_read;
        progress.contacts_found += contacts_found;
        self.save_locked(&progress)
    }

    pub fn cleanup(&self) -> Result<()> {
        if self.save_path.exists() {
            fs::remove_file(&self.save_path)?;
        }
        Ok(())
    }

    fn save_locked(&self, progress: &Progress) -> Result<()> {
        let json = serde_json::to_string_pretty(progress)?;
        fs::write(&self.save_path, json)?;
        Ok(())
    }
}
```

#### 3.3 Implement TLD Filter

```rust
// src/filter/tld.rs
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const TLD_SOURCE_URL: &str = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";

pub struct TldFilter {
    valid_tlds: HashSet<String>,
    disabled: bool,
}

impl TldFilter {
    pub fn new(tld_file_path: &Path, disabled: bool) -> Result<Self> {
        if disabled {
            log::info!("TLD filtering disabled");
            return Ok(Self {
                valid_tlds: HashSet::new(),
                disabled: true,
            });
        }

        let mut filter = Self {
            valid_tlds: HashSet::new(),
            disabled: false,
        };

        // Try to load from file
        if tld_file_path.exists() {
            filter.load_from_file(tld_file_path)?;
        }

        // If no TLDs loaded, try to download
        if filter.valid_tlds.is_empty() {
            log::info!("Downloading TLD list from IANA...");
            match filter.download_tlds() {
                Ok(tlds) => {
                    // Save to file for future use
                    if let Some(parent) = tld_file_path.parent() {
                        fs::create_dir_all(parent).ok();
                    }
                    fs::write(tld_file_path, tlds.join("\n")).ok();

                    for tld in tlds {
                        filter.valid_tlds.insert(tld.to_lowercase());
                    }
                }
                Err(e) => {
                    log::warn!("Failed to download TLDs: {}", e);
                }
            }
        }

        if filter.valid_tlds.is_empty() {
            log::warn!("No TLDs loaded, TLD filtering will be disabled");
            filter.disabled = true;
        } else {
            log::info!("Loaded {} valid TLDs", filter.valid_tlds.len());
        }

        Ok(filter)
    }

    pub fn is_valid_tld(&self, email: &str) -> bool {
        if self.disabled {
            return true;
        }

        let tld = email
            .rsplit('@')
            .next()
            .and_then(|domain| domain.rsplit('.').next())
            .map(|t| t.to_lowercase());

        tld.map(|t| self.valid_tlds.contains(&t)).unwrap_or(false)
    }

    fn load_from_file(&mut self, path: &Path) -> Result<()> {
        let content = fs::read_to_string(path)?;
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('#') {
                self.valid_tlds.insert(line.to_lowercase());
            }
        }
        Ok(())
    }

    fn download_tlds(&self) -> Result<Vec<String>> {
        let response = reqwest::blocking::get(TLD_SOURCE_URL)?;
        let content = response.text()?;

        Ok(content
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.trim().to_string())
            .collect())
    }
}
```

### Deliverables

- Thread-safe CSV writer with buffering
- Progress persistence compatible with Go's JSON format
- TLD filter with auto-download

---

## Phase 4: Parallel Processing & Resource Management (Days 15-20)

### Objectives

- Implement parallel file processing with rayon
- Add resource monitoring and throttling
- Create worker pool with dynamic sizing

### Tasks

#### 4.1 Implement Resource Manager

```rust
// src/resource/mod.rs
use sysinfo::{System, SystemExt, CpuExt};
use std::sync::Mutex;

pub struct ResourceLimits {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub min_free_memory_bytes: u64,
}

pub struct ResourceManager {
    system: Mutex<System>,
    limits: ResourceLimits,
    safe_mode: bool,
}

impl ResourceManager {
    pub fn new(limits: ResourceLimits, safe_mode: bool) -> Self {
        Self {
            system: Mutex::new(System::new_all()),
            limits,
            safe_mode,
        }
    }

    pub fn calculate_worker_count(&self, file_count: usize) -> usize {
        let mut sys = self.system.lock().unwrap();
        sys.refresh_all();

        let cpu_count = sys.cpus().len();
        let available_memory = sys.available_memory();

        // Estimate 256MB per worker for PST processing
        let memory_per_worker = 256 * 1024 * 1024;
        let memory_limited_workers = (available_memory / memory_per_worker) as usize;

        let mut workers = cpu_count.min(memory_limited_workers);

        if self.safe_mode {
            workers = (workers as f64 * 0.5).ceil() as usize;
        }

        workers.max(1).min(file_count).min(24)  // Cap at 24 workers
    }

    pub fn should_throttle(&self) -> bool {
        let mut sys = self.system.lock().unwrap();
        sys.refresh_cpu();
        sys.refresh_memory();

        let cpu_usage: f64 = sys.cpus()
            .iter()
            .map(|c| c.cpu_usage() as f64)
            .sum::<f64>() / sys.cpus().len() as f64;

        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        let memory_percent = (used_mem as f64 / total_mem as f64) * 100.0;
        let free_memory = sys.available_memory();

        cpu_usage > self.limits.cpu_percent
            || memory_percent > self.limits.memory_percent
            || free_memory < self.limits.min_free_memory_bytes
    }
}
```

#### 4.2 Implement Processor Orchestration

```rust
// src/processor/mod.rs
use rayon::prelude::*;
use dashmap::DashMap;
use std::sync::Arc;
use std::path::PathBuf;

pub struct Processor {
    config: Config,
    csv_writer: Arc<CsvWriter>,
    progress: Arc<ProgressTracker>,
    resource_mgr: Arc<ResourceManager>,
    tld_filter: Option<TldFilter>,
    contacts: DashMap<String, Contact>,
    extractor: PstExtractor,
}

impl Processor {
    pub fn new(config: Config) -> Result<Self> {
        let csv_writer = Arc::new(CsvWriter::new(&config.output_path, config.debug_mode)?);
        let progress = Arc::new(ProgressTracker::load_or_create(".progress.json"));

        let resource_mgr = Arc::new(ResourceManager::new(
            ResourceLimits {
                cpu_percent: config.cpu_limit,
                memory_percent: config.memory_limit,
                min_free_memory_bytes: config.min_free_memory_gb * 1024 * 1024 * 1024,
            },
            config.safe_mode,
        ));

        let tld_filter = if config.disable_tld_filter {
            None
        } else {
            let tld_path = config.output_path.parent()
                .unwrap_or(Path::new("."))
                .join("tlds-alpha-by-domain.txt");
            Some(TldFilter::new(&tld_path, false)?)
        };

        let extractor = PstExtractor::new(config.debug_mode, config.max_username_length);

        Ok(Self {
            config,
            csv_writer,
            progress,
            resource_mgr,
            tld_filter,
            contacts: DashMap::new(),
            extractor,
        })
    }

    pub fn process(&self) -> Result<()> {
        let files = self.collect_pst_files()?;

        if files.is_empty() {
            log::warn!("No PST files found in {:?}", self.config.folder_path);
            return Ok(());
        }

        log::info!("Found {} PST files to process", files.len());

        // Group files by size for better load balancing
        let file_groups = self.group_by_size(&files);

        for group in file_groups {
            self.process_file_group(group)?;
        }

        // Final flush - all contacts now in single unified CSV
        self.csv_writer.flush()?;

        // Cleanup progress file on success
        self.progress.cleanup()?;

        log::info!(
            "Extraction complete: {} unique contacts written to single CSV from {} PST files",
            self.contacts.len(),
            files.len()
        );

        Ok(())
    }

    fn collect_pst_files(&self) -> Result<Vec<PathBuf>> {
        let input = &self.config.input_path;

        // Handle single PST file
        if input.is_file() {
            if input.extension().map(|e| e.eq_ignore_ascii_case("pst")).unwrap_or(false) {
                return Ok(vec![input.clone()]);
            } else {
                return Err(PstWeeeError::ConfigError(
                    "Input file is not a PST file".to_string()
                ));
            }
        }

        // Handle folder containing PST files
        let mut files = Vec::new();

        for entry in fs::read_dir(input)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e.eq_ignore_ascii_case("pst")).unwrap_or(false) {
                files.push(path);
            }
        }

        Ok(files)
    }

    fn group_by_size(&self, files: &[PathBuf]) -> Vec<Vec<PathBuf>> {
        let mut groups: HashMap<u64, Vec<PathBuf>> = HashMap::new();

        for file in files {
            let size_group = file.metadata()
                .map(|m| m.len() / (100 * 1024 * 1024))  // 100MB groups
                .unwrap_or(0);

            groups.entry(size_group).or_default().push(file.clone());
        }

        groups.into_values().collect()
    }

    fn process_file_group(&self, files: Vec<PathBuf>) -> Result<()> {
        // Filter already completed files
        let remaining: Vec<_> = files
            .into_iter()
            .filter(|f| {
                let name = f.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                !self.progress.is_file_completed(name)
            })
            .collect();

        if remaining.is_empty() {
            return Ok(());
        }

        let worker_count = if self.config.max_workers > 0 {
            self.config.max_workers
        } else {
            self.resource_mgr.calculate_worker_count(remaining.len())
        };

        log::info!("Processing {} files with {} workers", remaining.len(), worker_count);

        // Configure thread pool
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count)
            .build()?;

        pool.install(|| {
            remaining.par_iter().for_each(|file| {
                self.process_single_file(file);
            });
        });

        Ok(())
    }

    fn process_single_file(&self, file: &Path) {
        let filename = file.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        log::info!("Processing: {}", filename);
        self.progress.set_current_file(filename).ok();

        match self.extractor.extract_contacts(file) {
            Ok(contacts) => {
                let mut new_contacts = 0u64;

                for contact in contacts {
                    // Validate
                    if !validate_email(&contact.email, self.config.max_username_length) {
                        continue;
                    }

                    // TLD check
                    if let Some(ref filter) = self.tld_filter {
                        if !filter.is_valid_tld(&contact.email) {
                            continue;
                        }
                    }

                    // Deduplicate
                    if !self.contacts.contains_key(&contact.email) {
                        self.contacts.insert(contact.email.clone(), contact.clone());

                        if let Err(e) = self.csv_writer.write_contact(&contact) {
                            log::error!("Failed to write contact: {}", e);
                        } else {
                            new_contacts += 1;
                        }
                    }
                }

                // Update progress
                let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
                self.progress.update_stats(file_size, new_contacts).ok();
                self.progress.mark_file_complete(filename).ok();

                // Flush periodically
                self.csv_writer.flush().ok();

                log::info!("Completed {}: {} new contacts", filename, new_contacts);
            }
            Err(e) => {
                log::error!("Error processing {}: {}", filename, e);
            }
        }
    }
}
```

### Deliverables

- Complete processor with parallel file processing
- Resource monitoring with dynamic worker scaling
- Throttling based on CPU/memory limits

---

## Phase 5: Testing & Benchmarking (Days 21-25)

### Objectives

- Comprehensive test suite
- Performance benchmarks comparing Go vs Rust
- Edge case handling

### Tasks

#### 5.1 Unit Tests

```rust
// tests/unit/email_validation.rs
#[cfg(test)]
mod email_tests {
    use pst_weee::filter::email::validate_email;

    #[test]
    fn test_valid_standard_emails() {
        let valid = vec![
            "user@example.com",
            "first.last@company.co.uk",
            "user+tag@domain.org",
            "a@b.io",
        ];

        for email in valid {
            assert!(validate_email(email, 20), "Should be valid: {}", email);
        }
    }

    #[test]
    fn test_invalid_emails() {
        let invalid = vec![
            "",
            "invalid",
            "@domain.com",
            "user@",
            "user@.com",
            "user..name@domain.com",
            "unsubscribe@example.com",
            "bounce@marketing.com",
        ];

        for email in invalid {
            assert!(!validate_email(email, 20), "Should be invalid: {}", email);
        }
    }

    #[test]
    fn test_username_length_filter() {
        assert!(validate_email("short@example.com", 20));
        assert!(!validate_email("verylongalphanumericusername@example.com", 20));
    }
}
```

#### 5.2 Integration Tests

```rust
// tests/integration/extraction.rs
use pst_weee::pst::PstExtractor;
use std::path::Path;
use tempfile::tempdir;

#[test]
#[ignore]  // Requires test PST file
fn test_full_extraction() {
    let test_pst = Path::new("tests/fixtures/sample.pst");
    if !test_pst.exists() {
        eprintln!("Skipping: test PST file not found");
        return;
    }

    let extractor = PstExtractor::new(true, 20);
    let contacts = extractor.extract_contacts(test_pst).unwrap();

    assert!(!contacts.is_empty());

    // Verify all contacts have valid emails
    for contact in &contacts {
        assert!(contact.email.contains('@'));
        assert!(!contact.email.is_empty());
    }
}

#[test]
fn test_csv_output_format() {
    let dir = tempdir().unwrap();
    let output = dir.path().join("test.csv");

    let writer = CsvWriter::new(&output, false).unwrap();

    writer.write_contact(&Contact {
        email: "test@example.com".to_string(),
        display_name: Some("Test User".to_string()),
    }).unwrap();

    writer.flush().unwrap();

    let content = std::fs::read_to_string(&output).unwrap();
    assert!(content.contains("Email,DisplayName"));
    assert!(content.contains("test@example.com,Test User"));
}
```

#### 5.3 Benchmarks

```rust
// benches/extraction_bench.rs
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use pst_weee::filter::email::validate_email;

fn email_validation_benchmark(c: &mut Criterion) {
    let emails = vec![
        "user@example.com",
        "very.long.email.address@subdomain.example.co.uk",
        "invalid-email-without-at",
        "unsubscribe@marketing.example.com",
    ];

    c.bench_function("email_validation_batch", |b| {
        b.iter(|| {
            for email in &emails {
                validate_email(email, 20);
            }
        })
    });
}

criterion_group!(benches, email_validation_benchmark);
criterion_main!(benches);
```

### Deliverables

- Unit tests for all modules
- Integration tests
- Performance benchmarks
- Test coverage report

---

## Phase 6: Documentation & Release (Days 26-28)

### Objectives

- Update README with Rust installation instructions
- Create migration guide
- Build release binaries

### Tasks

#### 6.1 Update README.md

- Installation via cargo
- Pre-built binary downloads
- Performance comparison with Go version

#### 6.2 Create GitHub Actions Workflow

```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
          - os: ubuntu-latest
            target: aarch64-unknown-linux-gnu
          - os: macos-latest
            target: x86_64-apple-darwin
          - os: macos-latest
            target: aarch64-apple-darwin
          - os: windows-latest
            target: x86_64-pc-windows-msvc

    runs-on: ${{ matrix.os }}

    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}

      - name: Build
        run: cargo build --release --target ${{ matrix.target }}

      - name: Upload artifact
        uses: actions/upload-artifact@v3
        with:
          name: pst_weee-${{ matrix.target }}
          path: target/${{ matrix.target }}/release/pst_weee*
```

#### 6.3 Create Cargo Release

```bash
cargo publish --dry-run
```

### Deliverables

- Updated documentation
- CI/CD pipeline
- Release binaries for all platforms
- Published crate (optional)

---

## Risk Mitigation

| Risk | Probability | Impact | Mitigation |
| ------ | ------------- | -------- | ------------ |
| `outlook-pst-rs` API incompatibility | Low | High | POC validation in Phase 0 |
| Performance regression | Medium | Medium | Benchmarks comparing Go vs Rust |
| PST format edge cases | Medium | Medium | Test with diverse PST samples |
| Cross-platform issues | Low | Medium | CI testing on all platforms |
| Memory leaks in parsing | Low | High | Use Rust's ownership + testing |

---

## Success Criteria

1. **Functionality**: All Go features working in Rust
2. **Performance**: Equal or better than Go implementation
3. **Compatibility**: Same CLI interface, same output format
4. **Output**: Single unified, deduplicated CSV file across all input PST files
5. **Testing**: >80% code coverage
6. **Deployment**: Single static binary, no runtime dependencies

---

## Post-Migration

1. **Deprecate Go version**: Update README to point to Rust
2. **Archive Go code**: Move to `legacy/` branch
3. **Monitor issues**: Track any compatibility reports
4. **Performance tuning**: Profile and optimize hot paths
