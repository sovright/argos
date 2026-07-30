//! zcashd wallet.dat record layer.

pub mod crypto;
pub mod plaintext;
pub mod records;

pub use crypto::{derive_master_key, find_mkey, MasterKey, MkeyRecord};
pub use plaintext::collect_plaintext;
pub use records::{compact_size, parse_record_key, RecordKey};
