//! Output module for CSV writing

mod csv;

pub use self::csv::{read_existing_contacts, CsvWriter};
