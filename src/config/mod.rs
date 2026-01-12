//! Configuration structures for Sparkle Pony

use crate::cli::Args;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for Sparkle Pony processor
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    /// Path to PST file or folder containing PST files
    pub input_path: PathBuf,

    /// Path to output CSV file
    pub output_path: PathBuf,

    /// Maximum CPU usage percentage (0-100)
    pub cpu_limit: f64,

    /// Maximum memory usage percentage (0-100)
    pub memory_limit: f64,

    /// Minimum free memory in GB
    pub min_free_memory_gb: u64,

    /// Maximum number of worker threads (0 = auto)
    pub max_workers: usize,

    /// Skip checking for available disk space
    pub ignore_space_check: bool,

    /// Enable safe mode with more conservative resource usage
    pub safe_mode: bool,

    /// Enable debug logging
    pub debug_mode: bool,

    /// Disable filtering of invalid TLDs
    pub disable_tld_filter: bool,

    /// Extract attachments when processing PSTs
    pub extract_attachments: bool,

    /// Size of chunks for processing in MB
    pub chunk_size_mb: usize,

    /// Maximum username length for email filtering
    pub max_username_length: usize,

    /// Skip extracting sender email addresses
    pub skip_senders: bool,

    /// Skip extracting recipient email addresses (To, CC, BCC)
    pub skip_recipients: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            input_path: PathBuf::new(),
            output_path: PathBuf::from("contacts.csv"),
            cpu_limit: 70.0,
            memory_limit: 70.0,
            min_free_memory_gb: 2,
            max_workers: 0,
            ignore_space_check: false,
            safe_mode: false,
            debug_mode: false,
            disable_tld_filter: false,
            extract_attachments: false,
            chunk_size_mb: 32,
            max_username_length: 20,
            skip_senders: false,
            skip_recipients: false,
        }
    }
}

impl From<Args> for Config {
    fn from(args: Args) -> Self {
        Self {
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
            skip_senders: args.skip_senders,
            skip_recipients: args.skip_recipients,
        }
    }
}
