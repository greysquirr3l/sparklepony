//! CSV output writing

use crate::error::Result;
use crate::pst::Contact;
use csv::{Reader, Writer};
use log::{debug, info};
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::sync::Mutex;

/// Thread-safe CSV writer for contact output
pub struct CsvWriter {
    writer: Mutex<Writer<BufWriter<File>>>,
    record_count: Mutex<u64>,
    #[allow(dead_code)]
    debug_mode: bool,
}

impl CsvWriter {
    /// Create a new CSV writer
    ///
    /// # Arguments
    /// * `output_path` - Path to the output CSV file
    /// * `debug_mode` - Enable debug logging
    ///
    /// # Errors
    /// Returns an error if the file cannot be created or written to.
    pub fn new(output_path: &Path, debug_mode: bool) -> Result<Self> {
        // Create parent directory if needed
        if let Some(parent) = output_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let file = File::create(output_path)?;
        let buf_writer = BufWriter::with_capacity(64 * 1024, file);
        let mut writer = Writer::from_writer(buf_writer);

        // Write header
        writer.write_record(["Email", "DisplayName"])?;
        writer.flush()?;

        debug!("Created CSV writer at {}", output_path.display());

        Ok(Self {
            writer: Mutex::new(writer),
            record_count: Mutex::new(0),
            debug_mode,
        })
    }

    /// Write a single contact to the CSV file
    ///
    /// # Errors
    /// Returns an error if writing fails.
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    #[allow(dead_code)]
    pub fn write_contact(&self, contact: &Contact) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        writer.write_record([
            &contact.email,
            contact.display_name.as_deref().unwrap_or(""),
        ])?;
        drop(writer);

        let mut count = self.record_count.lock().unwrap();
        *count += 1;
        drop(count);

        Ok(())
    }

    /// Write multiple contacts to the CSV file
    ///
    /// # Errors
    /// Returns an error if writing fails.
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    #[allow(clippy::significant_drop_tightening)]
    pub fn write_contacts(&self, contacts: &[Contact]) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        let mut count = self.record_count.lock().unwrap();

        for contact in contacts {
            writer.write_record([
                &contact.email,
                contact.display_name.as_deref().unwrap_or(""),
            ])?;
            *count += 1;
        }

        Ok(())
    }

    /// Flush the writer to ensure all data is written
    ///
    /// # Errors
    /// Returns an error if flushing fails.
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    pub fn flush(&self) -> Result<()> {
        let mut writer = self.writer.lock().unwrap();
        writer.flush()?;
        drop(writer);
        Ok(())
    }

    /// Get the number of records written
    ///
    /// # Panics
    /// Panics if the mutex is poisoned.
    pub fn record_count(&self) -> u64 {
        *self.record_count.lock().unwrap()
    }
}

/// Read existing contacts from a CSV file
///
/// # Arguments
/// * `path` - Path to the CSV file to read
///
/// # Returns
/// A vector of contacts read from the file, or empty vector if file doesn't exist
///
/// # Errors
/// Returns an error if the file exists but cannot be read or parsed.
pub fn read_existing_contacts(path: &Path) -> Result<Vec<Contact>> {
    if !path.exists() {
        debug!("No existing CSV file at {}", path.display());
        return Ok(Vec::new());
    }

    let file = File::open(path)?;
    let buf_reader = BufReader::new(file);
    let mut reader = Reader::from_reader(buf_reader);

    let mut contacts = Vec::new();

    for result in reader.records() {
        let record = result?;
        if !record.is_empty() {
            let email = record.get(0).unwrap_or("").to_string();
            let display_name = record
                .get(1)
                .map(ToString::to_string)
                .filter(|s| !s.is_empty());

            if !email.is_empty() {
                contacts.push(Contact::new(email, display_name));
            }
        }
    }

    info!(
        "Loaded {} existing contacts from {}",
        contacts.len(),
        path.display()
    );

    Ok(contacts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_csv_writer_creation() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("test.csv");
        let writer = CsvWriter::new(&output_path, false).unwrap();
        assert_eq!(writer.record_count(), 0);
    }

    #[test]
    fn test_csv_write_contact() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("test.csv");
        let writer = CsvWriter::new(&output_path, false).unwrap();

        let contact = Contact::new("test@example.com", Some("Test User".to_string()));
        writer.write_contact(&contact).unwrap();
        writer.flush().unwrap();

        assert_eq!(writer.record_count(), 1);

        // Verify file content
        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("Email,DisplayName"));
        assert!(content.contains("test@example.com,Test User"));
    }

    #[test]
    fn test_csv_write_multiple() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("test.csv");
        let writer = CsvWriter::new(&output_path, false).unwrap();

        let contacts = vec![
            Contact::new("a@example.com", Some("A".to_string())),
            Contact::new("b@example.com", None),
            Contact::new("c@example.com", Some("C".to_string())),
        ];

        writer.write_contacts(&contacts).unwrap();
        writer.flush().unwrap();

        assert_eq!(writer.record_count(), 3);
    }

    #[test]
    fn test_read_existing_contacts() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("test.csv");

        // Write some contacts first
        let writer = CsvWriter::new(&output_path, false).unwrap();
        let contacts = vec![
            Contact::new("alice@example.com", Some("Alice".to_string())),
            Contact::new("bob@example.com", Some("Bob".to_string())),
            Contact::new("charlie@example.com", None),
        ];
        writer.write_contacts(&contacts).unwrap();
        writer.flush().unwrap();
        drop(writer);

        // Read them back
        let loaded = read_existing_contacts(&output_path).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].email, "alice@example.com");
        assert_eq!(loaded[0].display_name, Some("Alice".to_string()));
        assert_eq!(loaded[1].email, "bob@example.com");
        assert_eq!(loaded[2].email, "charlie@example.com");
        assert_eq!(loaded[2].display_name, None);
    }

    #[test]
    fn test_read_nonexistent_file() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("nonexistent.csv");

        let loaded = read_existing_contacts(&output_path).unwrap();
        assert!(loaded.is_empty());
    }
}
