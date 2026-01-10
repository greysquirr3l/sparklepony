//! PST parsing and contact extraction

mod extractor;

pub use extractor::PstExtractor;

use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

/// Represents an extracted email contact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    /// Email address (lowercase, trimmed)
    pub email: String,
    /// Display name associated with the email (optional)
    pub display_name: Option<String>,
}

impl Contact {
    /// Create a new contact with normalized email
    pub fn new(email: impl Into<String>, display_name: Option<String>) -> Self {
        Self {
            email: email.into().to_lowercase().trim().to_string(),
            display_name: display_name
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        }
    }
}

impl PartialEq for Contact {
    fn eq(&self, other: &Self) -> bool {
        self.email == other.email
    }
}

impl Eq for Contact {}

impl Hash for Contact {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.email.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_normalization() {
        let contact = Contact::new("  John@Example.COM  ", Some("  John Doe  ".to_string()));
        assert_eq!(contact.email, "john@example.com");
        assert_eq!(contact.display_name, Some("John Doe".to_string()));
    }

    #[test]
    fn test_contact_empty_display_name() {
        let contact = Contact::new("test@example.com", Some("   ".to_string()));
        assert_eq!(contact.display_name, None);
    }

    #[test]
    fn test_contact_equality() {
        let c1 = Contact::new("test@example.com", Some("Test User".to_string()));
        let c2 = Contact::new("TEST@EXAMPLE.COM", Some("Different Name".to_string()));
        assert_eq!(c1, c2);
    }
}
