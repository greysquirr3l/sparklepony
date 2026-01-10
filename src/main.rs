//! PST WEEE - High-performance email contact extractor for Microsoft Outlook PST files
//!
//! This tool extracts email contacts from PST files and outputs them to a CSV file.
//! It supports parallel processing, resource management, and resumable progress tracking.

use anyhow::Result;
use clap::Parser;
use env_logger::Env;
use log::{error, info};
use std::time::Instant;

mod cli;
mod config;
mod error;
mod filter;
mod output;
mod processor;
mod progress;
mod pst;
mod resource;

use cli::Args;
use config::Config;
use processor::Processor;

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.debug { "debug" } else { "info" };
    env_logger::Builder::from_env(Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();

    info!("PST WEEE - Email Extractor");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Convert args to config
    let config: Config = args.into();

    info!("Input: {}", config.input_path.display());
    info!("Output file: {}", config.output_path.display());

    // Validate input path
    if !config.input_path.exists() {
        error!("Input path does not exist: {}", config.input_path.display());
        std::process::exit(1);
    }

    // Validate it's either a PST file or a directory
    let is_pst = config
        .input_path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("pst"));
    let is_dir = config.input_path.is_dir();

    if !is_pst && !is_dir {
        error!("Input must be a .pst file or a directory containing PST files");
        std::process::exit(1);
    }

    // Create output directory if needed
    if let Some(parent) = config.output_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let start = Instant::now();
    info!("Starting processing...");

    // Create and run processor
    let processor = Processor::new(config)?;
    processor.process()?;

    let elapsed = start.elapsed();
    info!("Processing completed in {elapsed:?}");

    Ok(())
}
