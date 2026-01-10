//! Email and TLD filtering

pub mod email;
mod tld;

pub use email::{contains_blacklisted_terms, validate_email};
pub use tld::TldFilter;
