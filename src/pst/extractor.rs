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
use outlook_pst::ndb::header::Header;
use outlook_pst::ndb::node_id::NodeId;
use outlook_pst::ndb::page::UnicodeBlockBTree;
use outlook_pst::ndb::root::Root;
use outlook_pst::PstFile;

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
    /// Whether to extract sender addresses
    extract_senders: bool,
    /// Whether to extract recipient addresses (To, CC, BCC)
    extract_recipients: bool,
}

impl PstExtractor {
    /// Create a new PST extractor
    #[must_use]
    pub const fn new(debug_mode: bool, max_username_length: usize) -> Self {
        Self {
            debug_mode,
            max_username_length,
            extract_senders: true,
            extract_recipients: true,
        }
    }

    /// Configure whether to extract sender addresses
    #[must_use]
    pub const fn with_senders(mut self, extract: bool) -> Self {
        self.extract_senders = extract;
        self
    }

    /// Configure whether to extract recipient addresses
    #[must_use]
    pub const fn with_recipients(mut self, extract: bool) -> Self {
        self.extract_recipients = extract;
        self
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
        self.process_folder(&store, &root_folder, &mut contacts, 0)?;

        debug!("Extracted {} unique contacts", contacts.len());

        Ok(contacts.into_values().collect())
    }

    /// Process a single folder and its subfolders
    #[allow(clippy::unnecessary_wraps)]
    fn process_folder(
        &self,
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
            // The row ID is already a complete NodeId with type embedded
            for row in contents_table.rows_matrix() {
                // Get the row ID - this is a complete NodeId
                let row_id_value: u32 = row.id().into();
                let node_id = NodeId::from(row_id_value);

                if let Ok(entry_id) = store.properties().make_entry_id(node_id) {
                    // Try to read the message and extract contacts
                    if let Err(e) = self.process_message(store, &entry_id, contacts) {
                        trace!("{indent}    Skipping message: {e}");
                    }
                }
            }
        }

        // Recurse into subfolders via hierarchy_table
        if let Some(hierarchy_table) = folder.hierarchy_table() {
            let subfolder_count = hierarchy_table.rows_matrix().count();
            trace!("{indent}  Found {subfolder_count} subfolders");

            for row in hierarchy_table.rows_matrix() {
                // Get the row ID - this IS the complete NodeId with type already embedded
                let row_id_value: u32 = row.id().into();
                trace!("{indent}    Trying subfolder with row_id: 0x{row_id_value:X}");

                // The row_id is already a complete NodeId, so just convert it
                let node_id = NodeId::from(row_id_value);

                match store.properties().make_entry_id(node_id) {
                    Ok(entry_id) => match UnicodeFolder::read(Rc::clone(store), &entry_id) {
                        Ok(subfolder) => {
                            if let Err(e) =
                                self.process_folder(store, &subfolder, contacts, depth + 1)
                            {
                                warn!("{indent}  Error processing subfolder: {e}");
                            }
                        }
                        Err(e) => trace!("{indent}    Failed to read subfolder: {e}"),
                    },
                    Err(e) => trace!("{indent}    Failed to make entry_id: {e}"),
                }
            }
        }

        Ok(())
    }

    /// Process a single message and extract contacts from it
    fn process_message(
        &self,
        store: &Rc<UnicodeStore>,
        entry_id: &EntryId,
        contacts: &mut HashMap<String, Contact>,
    ) -> Result<()> {
        // Read the message
        let message = UnicodeMessage::read(Rc::clone(store), entry_id, None)
            .map_err(|e| PstWeeeError::Pst(format!("Failed to read message: {e}")))?;

        // Extract sender from message properties
        if self.extract_senders {
            Self::extract_sender_from_message(&message, contacts);
        }

        // Extract recipients from recipient table
        if self.extract_recipients {
            Self::extract_recipients_from_message(store, &message, contacts);
        }

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
    /// Iterates through the recipient table and extracts email addresses
    /// for To, CC, and BCC recipients.
    fn extract_recipients_from_message(
        store: &Rc<UnicodeStore>,
        message: &Rc<UnicodeMessage>,
        contacts: &mut HashMap<String, Contact>,
    ) {
        let recipient_table = message.recipient_table();
        let context = recipient_table.context();
        let columns = context.columns();

        // Find column indices for properties we care about
        let email_col = columns.iter().position(|c| c.prop_id() == PR_EMAIL_ADDRESS);
        let smtp_col = columns.iter().position(|c| c.prop_id() == PR_SMTP_ADDRESS);
        let display_col = columns.iter().position(|c| c.prop_id() == PR_DISPLAY_NAME);

        trace!(
            "Recipient table: {} columns, {} rows (email_col={:?}, smtp_col={:?})",
            columns.len(),
            recipient_table.rows_matrix().count(),
            email_col,
            smtp_col
        );

        // We need access to the PST file reader and block btree
        let pst = store.pst();
        let header = pst.header();
        let root = header.root();
        let encoding = header.crypt_method();

        // Lock the file reader for the duration of extraction
        let Ok(mut file) = pst.reader().lock() else {
            warn!("Failed to lock PST file for recipient extraction");
            return;
        };

        // Read the block btree
        let block_btree = match UnicodeBlockBTree::read(&mut *file, *root.block_btree()) {
            Ok(btree) => btree,
            Err(e) => {
                trace!("Failed to read block btree: {e}");
                return;
            }
        };

        // Iterate through recipient rows
        for row in recipient_table.rows_matrix() {
            let Ok(row_columns) = row.columns(context) else {
                continue;
            };

            let mut email: Option<String> = None;
            let mut display_name: Option<String> = None;

            // Try to get SMTP address first (preferred)
            if let Some(idx) = smtp_col {
                if let Some(Some(value)) = row_columns.get(idx) {
                    if let Ok(prop_value) = recipient_table.read_column(
                        &mut *file,
                        encoding,
                        &block_btree,
                        value,
                        columns[idx].prop_type(),
                    ) {
                        email = Self::property_value_to_string(&prop_value);
                    }
                }
            }

            // Fall back to email address property
            if email.is_none() {
                if let Some(idx) = email_col {
                    if let Some(Some(value)) = row_columns.get(idx) {
                        if let Ok(prop_value) = recipient_table.read_column(
                            &mut *file,
                            encoding,
                            &block_btree,
                            value,
                            columns[idx].prop_type(),
                        ) {
                            email = Self::property_value_to_string(&prop_value);
                        }
                    }
                }
            }

            // Get display name
            if let Some(idx) = display_col {
                if let Some(Some(value)) = row_columns.get(idx) {
                    if let Ok(prop_value) = recipient_table.read_column(
                        &mut *file,
                        encoding,
                        &block_btree,
                        value,
                        columns[idx].prop_type(),
                    ) {
                        display_name = Self::property_value_to_string(&prop_value);
                    }
                }
            }

            // Add contact if we found an email
            if let Some(ref e) = email {
                Self::add_contact(contacts, e, display_name.as_deref());
            }
        }
    }

    /// Convert a `PropertyValue` to an optional String
    fn property_value_to_string(value: &PropertyValue) -> Option<String> {
        match value {
            PropertyValue::String8(s) => Some(s.to_string()),
            PropertyValue::Unicode(s) => Some(s.to_string()),
            _ => None,
        }
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
