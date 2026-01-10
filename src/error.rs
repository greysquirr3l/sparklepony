//! Error types for PST WEEE

use thiserror::Error;

/// Main error type for PST WEEE operations
#[derive(Error, Debug)]
#[allow(dead_code)] // Some variants are reserved for future use
pub enum PstWeeeError {
    /// Error opening or parsing PST file
    #[error("PST error: {0}")]
    Pst(String),

    /// I/O error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// CSV writing error
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),

    /// JSON serialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid configuration
    #[error("Configuration error: {0}")]
    Config(String),

    /// Progress persistence error
    #[error("Progress error: {0}")]
    Progress(String),

    /// Resource limit exceeded
    #[error("Resource error: {0}")]
    Resource(String),

    /// Email validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Path-related error
    #[error("Path error: {0}")]
    Path(String),

    /// HTTP request error (for TLD download)
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

/// Result type alias for PST WEEE operations
pub type Result<T> = std::result::Result<T, PstWeeeError>;

impl From<outlook_pst::PstError> for PstWeeeError {
    fn from(err: outlook_pst::PstError) -> Self {
        Self::Pst(err.to_string())
    }
}
