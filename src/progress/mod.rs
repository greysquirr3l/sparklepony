//! Progress tracking with JSON persistence

use crate::error::Result;
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Default progress file name
const PROGRESS_FILE: &str = ".pst_weee_progress.json";

/// Progress tracking state
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProgressState {
    /// Set of completed file names
    pub completed_files: HashSet<String>,
    /// Currently processing file
    pub current_file: Option<String>,
    /// Total contacts found
    pub contacts_found: u64,
    /// Total bytes read
    pub bytes_read: u64,
    /// Profile name (optional)
    pub profile_name: Option<String>,
    /// Additional configuration options
    #[serde(default)]
    pub config_options: HashMap<String, serde_json::Value>,
}

/// Progress tracker with persistence
pub struct ProgressTracker {
    state: Mutex<ProgressState>,
    save_path: PathBuf,
}

impl ProgressTracker {
    /// Load existing progress or create new tracker
    #[must_use]
    pub fn load_or_create(save_dir: &Path) -> Self {
        let save_path = save_dir.join(PROGRESS_FILE);
        let state = if save_path.exists() {
            match fs::read_to_string(&save_path) {
                Ok(content) => match serde_json::from_str(&content) {
                    Ok(state) => {
                        debug!("Loaded existing progress from {}", save_path.display());
                        state
                    }
                    Err(e) => {
                        warn!("Failed to parse progress file: {e}. Starting fresh.");
                        ProgressState::default()
                    }
                },
                Err(e) => {
                    warn!("Failed to read progress file: {e}. Starting fresh.");
                    ProgressState::default()
                }
            }
        } else {
            debug!("No existing progress file. Starting fresh.");
            ProgressState::default()
        };

        Self {
            state: Mutex::new(state),
            save_path,
        }
    }

    /// Check if a file has already been processed
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    pub fn is_file_completed(&self, filename: &str) -> bool {
        let state = self.state.lock().unwrap();
        state.completed_files.contains(filename)
    }

    /// Mark a file as completed
    ///
    /// # Errors
    /// Returns an error if saving progress fails.
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    pub fn mark_file_complete(&self, filename: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.completed_files.insert(filename.to_string());
        state.current_file = None;
        let result = self.save_locked(&state);
        drop(state);
        result
    }

    /// Set the currently processing file
    ///
    /// # Errors
    /// Returns an error if saving progress fails.
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    #[allow(dead_code)]
    pub fn set_current_file(&self, filename: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.current_file = Some(filename.to_string());
        let result = self.save_locked(&state);
        drop(state);
        result
    }

    /// Update statistics
    ///
    /// # Errors
    /// Returns an error if saving progress fails.
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    pub fn update_stats(&self, bytes_read: u64, contacts_found: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.bytes_read = bytes_read;
        state.contacts_found = contacts_found;
        let result = self.save_locked(&state);
        drop(state);
        result
    }

    /// Increment contacts found
    ///
    /// # Errors
    /// Returns an error if saving progress fails.
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    #[allow(dead_code)]
    pub fn add_contacts(&self, count: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.contacts_found += count;
        let result = self.save_locked(&state);
        drop(state);
        result
    }

    /// Get current progress state
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    #[allow(dead_code)]
    pub fn get_state(&self) -> ProgressState {
        self.state.lock().unwrap().clone()
    }

    /// Get number of completed files
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    pub fn completed_count(&self) -> usize {
        self.state.lock().unwrap().completed_files.len()
    }

    /// Get total contacts found
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    #[allow(dead_code)]
    pub fn contacts_found(&self) -> u64 {
        self.state.lock().unwrap().contacts_found
    }

    /// Clean up progress file (call after successful completion)
    ///
    /// # Errors
    /// Returns an error if the progress file cannot be removed.
    pub fn cleanup(&self) -> Result<()> {
        if self.save_path.exists() {
            fs::remove_file(&self.save_path)?;
            debug!("Removed progress file {}", self.save_path.display());
        }
        Ok(())
    }

    /// Save state to file (internal, called with lock held)
    fn save_locked(&self, state: &ProgressState) -> Result<()> {
        let json = serde_json::to_string_pretty(state)?;
        fs::write(&self.save_path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_progress_tracker_new() {
        let dir = tempdir().unwrap();
        let tracker = ProgressTracker::load_or_create(dir.path());
        assert_eq!(tracker.completed_count(), 0);
        assert_eq!(tracker.contacts_found(), 0);
    }

    #[test]
    fn test_progress_file_completion() {
        let dir = tempdir().unwrap();
        let tracker = ProgressTracker::load_or_create(dir.path());

        assert!(!tracker.is_file_completed("test.pst"));
        tracker.mark_file_complete("test.pst").unwrap();
        assert!(tracker.is_file_completed("test.pst"));
    }

    #[test]
    fn test_progress_persistence() {
        let dir = tempdir().unwrap();

        // Create and modify tracker
        {
            let tracker = ProgressTracker::load_or_create(dir.path());
            tracker.mark_file_complete("file1.pst").unwrap();
            tracker.mark_file_complete("file2.pst").unwrap();
            tracker.add_contacts(100).unwrap();
        }

        // Load again and verify
        {
            let tracker = ProgressTracker::load_or_create(dir.path());
            assert_eq!(tracker.completed_count(), 2);
            assert!(tracker.is_file_completed("file1.pst"));
            assert!(tracker.is_file_completed("file2.pst"));
            assert_eq!(tracker.contacts_found(), 100);
        }
    }

    #[test]
    fn test_progress_cleanup() {
        let dir = tempdir().unwrap();
        let tracker = ProgressTracker::load_or_create(dir.path());
        tracker.mark_file_complete("test.pst").unwrap();

        let progress_file = dir.path().join(PROGRESS_FILE);
        assert!(progress_file.exists());

        tracker.cleanup().unwrap();
        assert!(!progress_file.exists());
    }
}
