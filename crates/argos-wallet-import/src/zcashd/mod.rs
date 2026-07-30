//! zcashd wallet.dat record layer.

pub mod records;

pub use records::{compact_size, parse_record_key, RecordKey};
