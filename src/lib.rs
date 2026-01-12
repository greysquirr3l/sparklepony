//! Sparkle Pony library - Core functionality for PST email extraction

#![allow(clippy::multiple_crate_versions)] // Transitive dependencies

pub mod cli;
pub mod config;
pub mod error;
pub mod filter;
pub mod output;
pub mod processor;
pub mod progress;
pub mod pst;
pub mod resource;

pub use config::Config;
pub use error::{PstWeeeError, Result};
pub use pst::Contact;
