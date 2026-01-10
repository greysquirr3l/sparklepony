//! TLD (Top-Level Domain) validation and filtering

use crate::error::{PstWeeeError, Result};
use log::{debug, info, warn};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// URL for downloading the official IANA TLD list
const TLD_SOURCE_URL: &str = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";

/// Default TLD cache file name
const TLD_CACHE_FILE: &str = ".tld_cache.txt";

/// TLD filter for validating email domain TLDs
pub struct TldFilter {
    /// Set of valid TLDs (lowercase)
    valid_tlds: HashSet<String>,
    /// Whether the filter is disabled
    disabled: bool,
}

impl TldFilter {
    /// Create a new TLD filter
    ///
    /// # Arguments
    /// * `cache_dir` - Directory to cache the TLD list
    /// * `disabled` - If true, all TLDs are considered valid
    ///
    /// # Errors
    /// Returns an error if the TLD list cannot be downloaded or loaded.
    pub fn new(cache_dir: &Path, disabled: bool) -> Result<Self> {
        if disabled {
            return Ok(Self {
                valid_tlds: HashSet::new(),
                disabled: true,
            });
        }

        let cache_path = cache_dir.join(TLD_CACHE_FILE);
        let mut filter = Self {
            valid_tlds: HashSet::new(),
            disabled: false,
        };

        // Try to load from cache first
        if cache_path.exists() {
            match filter.load_from_file(&cache_path) {
                Ok(()) => {
                    debug!("Loaded {} TLDs from cache", filter.valid_tlds.len());
                    return Ok(filter);
                }
                Err(e) => {
                    warn!("Failed to load TLD cache: {e}");
                }
            }
        }

        // Download fresh list
        match Self::download_tlds() {
            Ok(tlds) => {
                filter.valid_tlds = tlds.into_iter().collect();
                // Save to cache
                if let Err(e) = filter.save_to_file(&cache_path) {
                    warn!("Failed to save TLD cache: {e}");
                }
                info!("Downloaded and cached {} TLDs", filter.valid_tlds.len());
            }
            Err(e) => {
                warn!("Failed to download TLDs: {e}. Using built-in list.");
                filter.load_builtin_tlds();
            }
        }

        Ok(filter)
    }

    /// Check if a TLD is valid
    #[must_use]
    pub fn is_valid_tld(&self, email: &str) -> bool {
        if self.disabled {
            return true;
        }

        // Extract TLD from email
        email
            .rsplit('@')
            .next()
            .and_then(|domain| domain.rsplit('.').next())
            .is_some_and(|t| self.valid_tlds.contains(&t.to_lowercase()))
    }

    /// Load TLDs from a cache file
    fn load_from_file(&mut self, path: &Path) -> Result<()> {
        let content = fs::read_to_string(path)?;
        self.valid_tlds = content
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.trim().to_lowercase())
            .collect();
        Ok(())
    }

    /// Save TLDs to a cache file
    fn save_to_file(&self, path: &Path) -> Result<()> {
        let content: Vec<&str> = self.valid_tlds.iter().map(String::as_str).collect();
        fs::write(path, content.join("\n"))?;
        Ok(())
    }

    /// Download TLDs from IANA
    fn download_tlds() -> Result<Vec<String>> {
        let response = reqwest::blocking::get(TLD_SOURCE_URL)?;
        let text = response.text()?;

        let tlds: Vec<String> = text
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.trim().to_lowercase())
            .collect();

        if tlds.is_empty() {
            return Err(PstWeeeError::Validation(
                "Downloaded TLD list is empty".to_string(),
            ));
        }

        Ok(tlds)
    }

    /// Load built-in common TLDs as fallback
    #[allow(clippy::too_many_lines)]
    fn load_builtin_tlds(&mut self) {
        let common_tlds = vec![
            "com",
            "org",
            "net",
            "edu",
            "gov",
            "mil",
            "int",
            "co",
            "io",
            "us",
            "uk",
            "de",
            "fr",
            "es",
            "it",
            "nl",
            "be",
            "at",
            "ch",
            "au",
            "nz",
            "ca",
            "jp",
            "cn",
            "kr",
            "in",
            "br",
            "mx",
            "ru",
            "pl",
            "se",
            "no",
            "fi",
            "dk",
            "ie",
            "pt",
            "cz",
            "hu",
            "ro",
            "bg",
            "gr",
            "tr",
            "za",
            "ae",
            "sg",
            "hk",
            "tw",
            "id",
            "th",
            "my",
            "ph",
            "vn",
            "info",
            "biz",
            "name",
            "pro",
            "mobi",
            "travel",
            "jobs",
            "museum",
            "aero",
            "coop",
            "asia",
            "cat",
            "tel",
            "xxx",
            "post",
            "bike",
            "clothing",
            "guru",
            "holdings",
            "plumbing",
            "singles",
            "ventures",
            "camera",
            "equipment",
            "estate",
            "gallery",
            "graphics",
            "lighting",
            "photography",
            "construction",
            "contractors",
            "directory",
            "kitchen",
            "land",
            "today",
            "technology",
            "tips",
            "voyage",
            "enterprises",
            "email",
            "company",
            "solutions",
            "support",
            "systems",
            "agency",
            "properties",
            "reviews",
            "marketing",
            "management",
            "academy",
            "center",
            "computer",
            "training",
            "education",
            "institute",
            "repair",
            "camp",
            "glass",
            "solar",
            "coffee",
            "florist",
            "house",
            "international",
            "ninja",
            "zone",
            "cool",
            "watch",
            "works",
            "expert",
            "foundation",
            "exposed",
            "fail",
            "villas",
            "bargains",
            "boutique",
            "cheap",
            "wtf",
            "cricket",
            "party",
            "science",
            "download",
            "racing",
            "accountant",
            "date",
            "faith",
            "loan",
            "review",
            "stream",
            "trade",
            "webcam",
            "win",
            "bid",
            "men",
            "click",
            "link",
            "work",
            "world",
            "app",
            "dev",
            "page",
            "cloud",
            "online",
            "site",
            "website",
            "tech",
            "store",
            "shop",
            "blog",
            "live",
            "life",
            "health",
            "fitness",
            "food",
            "network",
            "digital",
            "media",
            "social",
            "video",
            "games",
            "fun",
            "money",
            "finance",
            "bank",
            "insurance",
            "legal",
            "news",
            "sport",
            "family",
            "pet",
            "baby",
            "style",
            "fashion",
            "beauty",
            "design",
            "art",
            "music",
            "movie",
            "tv",
            "show",
        ];

        self.valid_tlds = common_tlds.into_iter().map(str::to_string).collect();
        debug!("Loaded {} built-in TLDs", self.valid_tlds.len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_disabled_filter() {
        let dir = tempdir().unwrap();
        let filter = TldFilter::new(dir.path(), true).unwrap();
        assert!(filter.is_valid_tld("user@example.anything"));
    }

    #[test]
    fn test_builtin_tlds() {
        let mut filter = TldFilter {
            valid_tlds: HashSet::new(),
            disabled: false,
        };
        filter.load_builtin_tlds();

        assert!(filter.is_valid_tld("user@example.com"));
        assert!(filter.is_valid_tld("user@example.org"));
        assert!(filter.is_valid_tld("user@example.io"));
        assert!(!filter.is_valid_tld("user@example.invalidtld123"));
    }

    #[test]
    fn test_tld_extraction() {
        let mut filter = TldFilter {
            valid_tlds: HashSet::new(),
            disabled: false,
        };
        filter.valid_tlds.insert("com".to_string());

        assert!(filter.is_valid_tld("user@example.com"));
        assert!(filter.is_valid_tld("user@sub.domain.example.com"));
        assert!(!filter.is_valid_tld("user@example.net"));
    }
}
