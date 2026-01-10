//! Main processor orchestration with parallel processing

use crate::config::Config;
use crate::error::{PstWeeeError, Result};
use crate::filter::{contains_blacklisted_terms, validate_email, TldFilter};
use crate::output::CsvWriter;
use crate::progress::ProgressTracker;
use crate::pst::{Contact, PstExtractor};
use crate::resource::{ResourceLimits, ResourceManager};
use dashmap::DashMap;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Batch size for CSV writes
const BATCH_SIZE: usize = 1000;

/// Main processor for PST contact extraction
pub struct Processor {
    config: Config,
    csv_writer: Arc<CsvWriter>,
    progress: Arc<ProgressTracker>,
    #[allow(dead_code)]
    resource_mgr: ResourceManager,
    tld_filter: Arc<TldFilter>,
    /// Concurrent map for contact deduplication
    contacts: Arc<DashMap<String, Contact>>,
    /// Counter for processed files
    files_processed: AtomicU64,
}

impl Processor {
    /// Create a new processor with the given configuration
    ///
    /// # Errors
    /// Returns an error if the CSV writer or TLD filter fails to initialize.
    pub fn new(config: Config) -> Result<Self> {
        // Create CSV writer
        let csv_writer = Arc::new(CsvWriter::new(&config.output_path, config.debug_mode)?);

        // Create progress tracker
        let progress_dir = config
            .input_path
            .parent()
            .unwrap_or(&config.input_path)
            .to_path_buf();
        let progress = Arc::new(ProgressTracker::load_or_create(&progress_dir));

        // Create resource manager
        let resource_limits = ResourceLimits {
            cpu_percent: config.cpu_limit,
            memory_percent: config.memory_limit,
            min_free_memory: config.min_free_memory_gb * 1024 * 1024 * 1024,
        };
        let resource_mgr = ResourceManager::new(resource_limits, config.safe_mode);

        // Create TLD filter
        let tld_filter = Arc::new(TldFilter::new(&progress_dir, config.disable_tld_filter));

        // Create extractor (will be cloned per-thread)
        let contacts = Arc::new(DashMap::new());

        info!(
            "Processor initialized. Safe mode: {}, TLD filter: {}",
            config.safe_mode,
            if config.disable_tld_filter {
                "disabled"
            } else {
                "enabled"
            }
        );

        Ok(Self {
            config,
            csv_writer,
            progress,
            resource_mgr,
            tld_filter,
            contacts,
            files_processed: AtomicU64::new(0),
        })
    }

    /// Process all PST files
    ///
    /// # Errors
    /// Returns an error if file collection or CSV writing fails.
    ///
    /// # Panics
    /// May panic if progress bar template is invalid.
    pub fn process(&self) -> Result<()> {
        // Collect PST files
        let files = self.collect_pst_files()?;

        if files.is_empty() {
            warn!("No PST files found to process");
            return Ok(());
        }

        info!("Found {} PST file(s) to process", files.len());

        // Filter out already completed files
        let pending_files: Vec<PathBuf> = files
            .into_iter()
            .filter(|f| {
                let filename = f.file_name().unwrap_or_default().to_string_lossy();
                !self.progress.is_file_completed(&filename)
            })
            .collect();

        if pending_files.is_empty() {
            info!("All files already processed. Use --force to reprocess.");
            self.write_contacts_to_csv()?;
            return Ok(());
        }

        info!(
            "{} file(s) pending, {} already completed",
            pending_files.len(),
            self.progress.completed_count()
        );

        // Calculate worker count
        let mut resource_mgr = ResourceManager::new(
            ResourceLimits {
                cpu_percent: self.config.cpu_limit,
                memory_percent: self.config.memory_limit,
                min_free_memory: self.config.min_free_memory_gb * 1024 * 1024 * 1024,
            },
            self.config.safe_mode,
        );
        let worker_count =
            resource_mgr.calculate_worker_count(pending_files.len(), self.config.max_workers);

        // Configure rayon thread pool
        rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count)
            .build_global()
            .unwrap_or_else(|e| {
                warn!("Failed to configure thread pool: {e}. Using default.");
            });

        // Create progress bar
        let progress_bar = ProgressBar::new(pending_files.len() as u64);
        progress_bar.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                .unwrap()
                .progress_chars("█▓░"),
        );

        // Process files in parallel
        pending_files.par_iter().for_each(|pst_path| {
            let filename = pst_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            progress_bar.set_message(filename.clone());

            match self.process_single_file(pst_path) {
                Ok(count) => {
                    debug!("Extracted {count} contacts from {filename}");
                    if let Err(e) = self.progress.mark_file_complete(&filename) {
                        warn!("Failed to save progress for {filename}: {e}");
                    }
                }
                Err(e) => {
                    error!("Failed to process {filename}: {e}");
                }
            }

            self.files_processed.fetch_add(1, Ordering::SeqCst);
            progress_bar.inc(1);
        });

        progress_bar.finish_with_message("Processing complete");

        // Write all contacts to CSV
        self.write_contacts_to_csv()?;

        // Update and cleanup progress
        let total_contacts = self.contacts.len() as u64;
        self.progress
            .update_stats(0, total_contacts)
            .unwrap_or_else(|e| warn!("Failed to update progress stats: {e}"));

        self.progress
            .cleanup()
            .unwrap_or_else(|e| warn!("Failed to cleanup progress file: {e}"));

        info!(
            "Processed {} files, extracted {} unique contacts",
            self.files_processed.load(Ordering::SeqCst),
            total_contacts
        );

        Ok(())
    }

    /// Collect all PST files from the input path
    fn collect_pst_files(&self) -> Result<Vec<PathBuf>> {
        let input_path = &self.config.input_path;

        if input_path.is_file() {
            // Single file
            if input_path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("pst"))
            {
                return Ok(vec![input_path.clone()]);
            }
            return Err(PstWeeeError::Path(format!(
                "Input file is not a PST file: {}",
                input_path.display()
            )));
        }

        if input_path.is_dir() {
            // Directory - collect all PST files
            let mut pst_files = Vec::new();
            for entry in std::fs::read_dir(input_path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file()
                    && path
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("pst"))
                {
                    pst_files.push(path);
                }
            }

            // Sort by size (largest first for better load balancing)
            pst_files.sort_by(|a, b| {
                let size_a = std::fs::metadata(a).map(|m| m.len()).unwrap_or(0);
                let size_b = std::fs::metadata(b).map(|m| m.len()).unwrap_or(0);
                size_b.cmp(&size_a)
            });

            return Ok(pst_files);
        }

        Err(PstWeeeError::Path(format!(
            "Input path does not exist: {}",
            input_path.display()
        )))
    }

    /// Process a single PST file
    fn process_single_file(&self, pst_path: &Path) -> Result<usize> {
        let extractor = PstExtractor::new(self.config.debug_mode, self.config.max_username_length)
            .with_senders(!self.config.skip_senders)
            .with_recipients(!self.config.skip_recipients);

        let raw_contacts = extractor.extract_contacts(pst_path)?;

        let mut added_count = 0;

        for contact in raw_contacts {
            // Apply filters
            if !self.should_include_contact(&contact) {
                continue;
            }

            // Add to deduplicated map (only if not present)
            let email_key = contact.email.clone();
            if !self.contacts.contains_key(&email_key) {
                self.contacts.insert(email_key, contact);
                added_count += 1;
            }
        }

        Ok(added_count)
    }

    /// Check if a contact should be included based on filters
    fn should_include_contact(&self, contact: &Contact) -> bool {
        // Validate email format
        if !validate_email(&contact.email, self.config.max_username_length) {
            return false;
        }

        // Check blacklisted terms
        if contains_blacklisted_terms(&contact.email) {
            return false;
        }

        // Check TLD
        if !self.tld_filter.is_valid_tld(&contact.email) {
            return false;
        }

        true
    }

    /// Write all collected contacts to the CSV file
    fn write_contacts_to_csv(&self) -> Result<()> {
        info!("Writing {} contacts to CSV...", self.contacts.len());

        // Collect and sort contacts for consistent output
        let mut contacts: Vec<Contact> = self
            .contacts
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        contacts.sort_by(|a, b| a.email.cmp(&b.email));

        // Write in batches
        for chunk in contacts.chunks(BATCH_SIZE) {
            self.csv_writer.write_contacts(chunk)?;
        }

        self.csv_writer.flush()?;

        info!(
            "Wrote {} contacts to {}",
            self.csv_writer.record_count(),
            self.config.output_path.display()
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_processor_creation() {
        let dir = tempdir().unwrap();
        let config = Config {
            input_path: dir.path().to_path_buf(),
            output_path: dir.path().join("output.csv"),
            ..Default::default()
        };

        let processor = Processor::new(config);
        assert!(processor.is_ok());
    }

    #[test]
    fn test_contact_filtering() {
        let dir = tempdir().unwrap();
        let config = Config {
            input_path: dir.path().to_path_buf(),
            output_path: dir.path().join("output.csv"),
            ..Default::default()
        };

        let processor = Processor::new(config).unwrap();

        // Valid contact
        let valid = Contact::new("john@example.com".to_string(), Some("John".to_string()));
        assert!(processor.should_include_contact(&valid));

        // Invalid - blacklisted
        let blacklisted = Contact::new(
            "noreply@example.com".to_string(),
            Some("No Reply".to_string()),
        );
        assert!(!processor.should_include_contact(&blacklisted));
    }
}
