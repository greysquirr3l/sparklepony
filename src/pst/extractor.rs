//! PST file contact extraction using outlook-pst crate
//!
//! This module provides native Rust PST parsing without requiring external
//! tools like libpst/readpst. It uses the outlook-pst crate which implements
//! the MS-PST specification.

use crate::error::{PstWeeeError, Result};
use crate::pst::Contact;
use log::{debug, trace, warn};
use outlook_pst::ltp::prop_context::PropertyValue;
use outlook_pst::messaging::folder::UnicodeFolder;
use outlook_pst::messaging::message::UnicodeMessage;
use outlook_pst::messaging::store::{EntryId, UnicodeStore};
use outlook_pst::ndb::node_id::{NodeId, NodeIdType};

use outlook_pst::UnicodePstFile;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;

// MAPI Property IDs for email extraction
// See: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxprops/
const PR_SENDER_EMAIL_ADDRESS: u16 = 0x0C1F;
const PR_SENDER_NAME: u16 = 0x0C1A;
const PR_EMAIL_ADDRESS: u16 = 0x3003;
const PR_DISPLAY_NAME: u16 = 0x3001;
const PR_SMTP_ADDRESS: u16 = 0x39FE;

/// Extracts contacts from PST files using native Rust parsing
pub struct PstExtractor {
    /// Enable debug output
    debug_mode: bool,
    /// Maximum username length for filtering
    #[allow(dead_code)]
    max_username_length: usize,
}

impl PstExtractor {
    /// Create a new PST extractor
    #[must_use]
    pub const fn new(debug_mode: bool, max_username_length: usize) -> Self {
        Self {
            debug_mode,
            max_username_length,
        }
    }

    /// Extract contacts from a PST file
    ///
    /// Returns a vector of unique contacts found in the PST file.
    /// Deduplication is performed by email address (case-insensitive).
    ///
    /// # Errors
    /// Returns an error if the PST file cannot be opened or parsed.
    pub fn extract_contacts(&self, pst_path: &Path) -> Result<Vec<Contact>> {
        debug!("Opening PST file: {}", pst_path.display());

        // Open the PST file
        let pst = UnicodePstFile::open(pst_path)
            .map_err(|e| PstWeeeError::Pst(format!("Failed to open PST file: {e}")))?;

        let pst = Rc::new(pst);

        // Create the store
        let store = UnicodeStore::read(Rc::clone(&pst))
            .map_err(|e| PstWeeeError::Pst(format!("Failed to read PST store: {e}")))?;

        if self.debug_mode {
            if let Ok(name) = store.properties().display_name() {
                debug!("PST store: {name}");
            }
        }

        let mut contacts: HashMap<String, Contact> = HashMap::new();

        // Get the root folder entry ID
        let root_entry_id = store
            .properties()
            .ipm_sub_tree_entry_id()
            .map_err(|e| PstWeeeError::Pst(format!("Failed to get root folder: {e}")))?;

        // Read the root folder
        let root_folder = UnicodeFolder::read(Rc::clone(&store), &root_entry_id)
            .map_err(|e| PstWeeeError::Pst(format!("Failed to read root folder: {e}")))?;

        // Traverse the folder hierarchy
        Self::process_folder(&store, &root_folder, &mut contacts, 0)?;

        debug!("Extracted {} unique contacts", contacts.len());

        Ok(contacts.into_values().collect())
    }

    /// Process a single folder and its subfolders
    #[allow(clippy::unnecessary_wraps)]
    fn process_folder(
        store: &Rc<UnicodeStore>,
        folder: &Rc<UnicodeFolder>,
        contacts: &mut HashMap<String, Contact>,
        depth: usize,
    ) -> Result<()> {
        let indent = "  ".repeat(depth);
        if let Ok(name) = folder.properties().display_name() {
            trace!("{indent}Processing folder: {name}");
        }

        // Process messages in this folder via contents_table
        if let Some(contents_table) = folder.contents_table() {
            // rows_matrix() returns an iterator, so use count() instead of len()
            let row_count = contents_table.rows_matrix().count();
            trace!("{indent}  Found {row_count} messages");

            // Iterate through contents table to get message entry IDs
            // The contents table has row IDs that can be used to construct entry IDs
            for row in contents_table.rows_matrix() {
                // Get the row ID - convert TableRowId to u32
                let row_id_value: u32 = row.id().into();

                // Create NodeId for the message
                if let Ok(node_id) = NodeId::new(NodeIdType::NormalMessage, row_id_value) {
                    if let Ok(entry_id) = store.properties().make_entry_id(node_id) {
                        // Try to read the message and extract contacts
                        if let Err(e) = Self::process_message(store, &entry_id, contacts) {
                            trace!("{indent}    Skipping message: {e}");
                        }
                    }
                }
            }
        }

        // Recurse into subfolders via hierarchy_table
        if let Some(hierarchy_table) = folder.hierarchy_table() {
            for row in hierarchy_table.rows_matrix() {
                // Get the row ID - convert TableRowId to u32
                let row_id_value: u32 = row.id().into();

                // Create NodeId for the folder
                if let Ok(node_id) = NodeId::new(NodeIdType::NormalFolder, row_id_value) {
                    if let Ok(entry_id) = store.properties().make_entry_id(node_id) {
                        if let Ok(subfolder) = UnicodeFolder::read(Rc::clone(store), &entry_id) {
                            if let Err(e) =
                                Self::process_folder(store, &subfolder, contacts, depth + 1)
                            {
                                warn!("{indent}  Error processing subfolder: {e}");
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process a single message and extract contacts from it
    fn process_message(
        store: &Rc<UnicodeStore>,
        entry_id: &EntryId,
        contacts: &mut HashMap<String, Contact>,
    ) -> Result<()> {
        // Read the message
        let message = UnicodeMessage::read(Rc::clone(store), entry_id, None)
            .map_err(|e| PstWeeeError::Pst(format!("Failed to read message: {e}")))?;

        // Extract sender from message properties
        Self::extract_sender_from_message(&message, contacts);

        // Extract recipients from recipient table
        Self::extract_recipients_from_message(&message, contacts);

        Ok(())
    }

    /// Extract sender contact from message properties
    fn extract_sender_from_message(
        message: &Rc<UnicodeMessage>,
        contacts: &mut HashMap<String, Contact>,
    ) {
        let props = message.properties();

        // Try to get sender email from various properties
        let email = Self::get_property_string(props.get(PR_SENDER_EMAIL_ADDRESS))
            .or_else(|| Self::get_property_string(props.get(PR_SMTP_ADDRESS)))
            .or_else(|| Self::get_property_string(props.get(PR_EMAIL_ADDRESS)));

        let display_name = Self::get_property_string(props.get(PR_SENDER_NAME))
            .or_else(|| Self::get_property_string(props.get(PR_DISPLAY_NAME)));

        if let Some(email) = email {
            Self::add_contact(contacts, &email, display_name.as_deref());
        }
    }

    /// Extract recipients from message's recipient table
    ///
    /// Note: The recipient table uses the complex `TableContext` API.
    /// For simplicity, we extract basic string properties where available.
    fn extract_recipients_from_message(
        message: &Rc<UnicodeMessage>,
        _contacts: &mut HashMap<String, Contact>,
    ) {
        // The recipient table context has column metadata
        let recipient_table = message.recipient_table();
        let context = recipient_table.context();
        let columns = context.columns();

        // For each row in the recipient table, try to extract email data
        // Note: Full extraction requires more complex block reading -
        // for now we focus on the sender which is in message properties
        trace!(
            "Recipient table has {} columns and {} rows",
            columns.len(),
            recipient_table.rows_matrix().count()
        );

        // TODO: Implement full recipient extraction if needed
        // This requires accessing the PST file reader with proper locking
        // and using read_column() for each cell
    }

    /// Get a string value from a `PropertyValue`
    fn get_property_string(value: Option<&PropertyValue>) -> Option<String> {
        match value {
            Some(PropertyValue::String8(s)) => Some(s.to_string()),
            Some(PropertyValue::Unicode(s)) => Some(s.to_string()),
            _ => None,
        }
    }

    /// Add a contact to the map if the email is valid
    fn add_contact(
        contacts: &mut HashMap<String, Contact>,
        email: &str,
        display_name: Option<&str>,
    ) {
        let email_lower = email.to_lowercase().trim().to_string();

        if email_lower.is_empty() {
            return;
        }

        // Skip obviously invalid emails
        if !email_lower.contains('@') {
            return;
        }

        // Only add if not already present (keep first display name encountered)
        if let std::collections::hash_map::Entry::Vacant(e) = contacts.entry(email_lower) {
            let contact = Contact::new(email, display_name.map(str::to_string));
            e.insert(contact);
            trace!("Added contact: {email}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extractor_creation() {
        let extractor = PstExtractor::new(true, 20);
        assert!(extractor.debug_mode);
        assert_eq!(extractor.max_username_length, 20);
    }
}
