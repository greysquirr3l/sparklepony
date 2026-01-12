//! Email validation logic ported from Go implementation

use regex::Regex;
use serde::Deserialize;
use std::path::Path;
use std::sync::LazyLock;

/// Primary regex for filtering valid email formats
static EMAIL_FILTER_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^[A-Za-z0-9][A-Za-z0-9._%+-]*[A-Za-z0-9]@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
    ).expect("Invalid EMAIL_FILTER_REGEX pattern")
});

/// Hex pattern for auto-generated addresses
static HEX_PATTERN_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^([0-9a-f]{10,}-[0-9a-f-]+)@").expect("Invalid HEX_PATTERN_REGEX pattern")
});

/// Numeric prefix pattern
static NUMERIC_PREFIX_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^\d{3}-[a-z]{3}-\d{3}\.\d[.\d]+@")
        .expect("Invalid NUMERIC_PREFIX_REGEX pattern")
});

/// `U+` long pattern for encoded addresses
static U_PLUS_LONG_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^u\+[a-z0-9]{30,}@").expect("Invalid U_PLUS_LONG_REGEX pattern")
});

/// Digit check for TLD validation
static DIGIT_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d").expect("Invalid DIGIT_REGEX pattern"));

/// Email blacklist configuration loaded from RON file
#[derive(Debug, Deserialize)]
pub struct BlacklistConfig {
    /// Terms that indicate automated/system emails
    pub blacklisted_terms: Vec<String>,
    /// Patterns commonly found in test or auto-generated emails
    pub bad_patterns: Vec<String>,
}

impl Default for BlacklistConfig {
    fn default() -> Self {
        Self {
            blacklisted_terms: vec![
                "unsubscribe".into(),
                "unsub".into(),
                "abuse".into(),
                "amazonses".into(),
                "marketoemail".into(),
                "mktoemail.com".into(),
                "bounce".into(),
                "noreply".into(),
                "donotreply".into(),
                "optout".into(),
                "businesstrack.com".into(),
                "mktomail.com".into(),
                "messaging.squareup.com".into(),
                "dropbox.com".into(),
                "squarespace-mail.com".into(),
            ],
            bad_patterns: vec![
                "test@".into(),
                "@test.".into(),
                "example.com".into(),
                "example.net".into(),
                "example.org".into(),
                "user@".into(),
                "sample@".into(),
                "demo@".into(),
                "noreply@".into(),
                "no-reply@".into(),
                "donotreply@".into(),
                "invalid@".into(),
                "someone@".into(),
                "anybody@".into(),
                "nobody@".into(),
            ],
        }
    }
}

impl BlacklistConfig {
    /// Load blacklist configuration from a RON file
    ///
    /// # Errors
    /// Returns an error if the file cannot be read or parsed.
    pub fn load_from_file(path: &Path) -> Result<Self, BlacklistLoadError> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = ron::from_str(&content)?;
        Ok(config)
    }

    /// Load blacklist from file or use default if file doesn't exist
    #[must_use]
    pub fn load_or_default(path: &Path) -> Self {
        if path.exists() {
            Self::load_from_file(path).unwrap_or_else(|e| {
                log::warn!(
                    "Failed to load blacklist from {}: {e}. Using defaults.",
                    path.display()
                );
                Self::default()
            })
        } else {
            Self::default()
        }
    }

    /// Check if an email contains any blacklisted terms
    #[must_use]
    pub fn contains_blacklisted_term(&self, email: &str) -> bool {
        let email_lower = email.to_lowercase();
        self.blacklisted_terms
            .iter()
            .any(|term| email_lower.contains(term))
    }

    /// Check if an email contains any bad patterns
    #[must_use]
    pub fn contains_bad_pattern(&self, email: &str) -> bool {
        let email_lower = email.to_lowercase();
        self.bad_patterns
            .iter()
            .any(|pattern| email_lower.contains(pattern))
    }
}

/// Error type for blacklist loading
#[derive(Debug, thiserror::Error)]
pub enum BlacklistLoadError {
    /// IO error reading file
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// RON parse error
    #[error("RON parse error: {0}")]
    Ron(#[from] ron::error::SpannedError),
}

/// Global blacklist loaded lazily
static BLACKLIST: LazyLock<BlacklistConfig> = LazyLock::new(|| {
    let config_path = Path::new("config/blacklist.ron");
    BlacklistConfig::load_or_default(config_path)
});

/// Build a regex pattern for usernames longer than the specified length
fn build_long_username_regex(length: usize) -> Regex {
    let pattern = format!(r"(?i)^[A-Za-z0-9]{{{length}}}@");
    Regex::new(&pattern).expect("Invalid long username regex pattern")
}

/// Validate an email address format
///
/// # Arguments
/// * `email` - The email address to validate
/// * `max_username_length` - Maximum allowed username length (0 to skip this check)
///
/// # Returns
/// `true` if the email is valid, `false` otherwise
#[must_use]
pub fn validate_email(email: &str, max_username_length: usize) -> bool {
    // Skip empty emails
    if email.is_empty() {
        return false;
    }

    // Basic pattern checking
    if !EMAIL_FILTER_REGEX.is_match(email) {
        return false;
    }

    // Check for common invalid patterns
    if email.contains("..") || email.contains(".@") || email.matches('@').count() != 1 {
        return false;
    }

    // Check for long usernames
    if max_username_length > 0 {
        let long_username_regex = build_long_username_regex(max_username_length);
        if long_username_regex.is_match(email) {
            return false;
        }
    }

    // Check other rejection patterns
    if HEX_PATTERN_REGEX.is_match(email)
        || NUMERIC_PREFIX_REGEX.is_match(email)
        || U_PLUS_LONG_REGEX.is_match(email)
    {
        return false;
    }

    // Basic domain validation
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let domain = parts[1];

    // Domain should have at least one dot
    if !domain.contains('.') {
        return false;
    }

    // Check TLD length (most TLDs are 2-10 characters)
    let tld = domain.rsplit('.').next().unwrap_or("");
    if tld.len() < 2 || tld.len() > 10 {
        return false;
    }

    // Ensure TLD doesn't contain digits
    !DIGIT_REGEX.is_match(tld)
}

/// Check if an email contains blacklisted terms using global config
#[must_use]
pub fn contains_blacklisted_terms(email: &str) -> bool {
    BLACKLIST.contains_blacklisted_term(email)
}

/// Check if an email contains common bad patterns using global config
#[allow(dead_code)]
#[must_use]
pub fn contains_bad_patterns(email: &str) -> bool {
    BLACKLIST.contains_bad_pattern(email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(validate_email("user@example.com", 20));
        assert!(validate_email("john.doe@company.org", 20));
        assert!(validate_email("test123@domain.co.uk", 20));
        assert!(validate_email("name+tag@gmail.com", 20));
        assert!(validate_email("a1@short.io", 20));
    }

    #[test]
    fn test_invalid_emails() {
        assert!(!validate_email("", 20));
        assert!(!validate_email("invalid", 20));
        assert!(!validate_email("@domain.com", 20));
        assert!(!validate_email("user@", 20));
        assert!(!validate_email("user@domain", 20));
        assert!(!validate_email("user..name@domain.com", 20));
        assert!(!validate_email("user.@domain.com", 20));
        assert!(!validate_email("user@domain.123", 20));
    }

    #[test]
    fn test_long_username_rejection() {
        // Username with exactly 20 alphanumeric chars should be rejected
        assert!(!validate_email("abcdefghijklmnopqrst@example.com", 20));
        // Shorter should be fine
        assert!(validate_email("abcdefghij@example.com", 20));
    }

    #[test]
    fn test_hex_pattern_rejection() {
        assert!(!validate_email(
            "0123456789abcdef-1234-5678@example.com",
            20
        ));
    }

    #[test]
    fn test_blacklisted_terms() {
        assert!(contains_blacklisted_terms("unsubscribe@company.com"));
        assert!(contains_blacklisted_terms("noreply@company.com"));
        assert!(contains_blacklisted_terms("user@mktoemail.com"));
        assert!(!contains_blacklisted_terms("john@company.com"));
    }

    #[test]
    fn test_bad_patterns() {
        assert!(contains_bad_patterns("test@company.com"));
        assert!(contains_bad_patterns("user@example.com"));
        assert!(contains_bad_patterns("noreply@company.com"));
        assert!(!contains_bad_patterns("john.doe@company.org"));
    }

    #[test]
    fn test_blacklist_config_default() {
        let config = BlacklistConfig::default();
        assert!(!config.blacklisted_terms.is_empty());
        assert!(!config.bad_patterns.is_empty());
    }

    #[test]
    fn test_blacklist_config_methods() {
        let config = BlacklistConfig::default();
        assert!(config.contains_blacklisted_term("noreply@test.com"));
        assert!(!config.contains_blacklisted_term("john@test.com"));
        assert!(config.contains_bad_pattern("test@company.com"));
        assert!(!config.contains_bad_pattern("john@company.com"));
    }
}
