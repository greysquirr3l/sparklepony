//! CLI argument parsing using clap

use clap::Parser;
use std::path::PathBuf;

/// PST WEEE - High-performance email contact extractor for PST files
#[derive(Parser, Debug)]
#[command(name = "pst_weee")]
#[command(author = "Nick Campbell")]
#[command(version)]
#[command(about = "High-performance email contact extractor for Microsoft Outlook PST files")]
#[command(long_about = None)]
#[allow(clippy::struct_excessive_bools)]
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
