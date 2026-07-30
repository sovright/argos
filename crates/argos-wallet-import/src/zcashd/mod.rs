//! zcashd wallet.dat record layer.

pub mod plaintext;
pub mod records;

pub use plaintext::collect_plaintext;
pub use records::{compact_size, parse_record_key, RecordKey};
