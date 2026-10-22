//! Durable broadcast history and the evidence that resolves it.
//!
//! Design rules this module enforces:
//!
//! - One registry per canonical `(data_dir, network)`, outside any
//!   scan-parameter-dependent workspace, guarded by the network operation
//!   lock. Aliases cannot bypass unresolved history; unrelated wallets in one
//!   data directory may conservatively block each other.
//! - Bytes are persisted before any network I/O. Only those exact bytes may be
//!   retried; no caller can supply replacement bytes for a recorded txid.
//! - Replies are classified narrowly: only stable, specific node reasons count
//!   as a deterministic rejection, and any other non-accept reply after
//!   network I/O is `SubmissionUnknown` with its fee at risk. A deterministic
//!   rejection is final (`Rejected`) only for bytes that no earlier reply or
//!   observation placed on the network.
//! - `Pending`, `SubmissionUnknown`, and `NotSubmitted` block a new review or
//!   execution after restart. Unknown is promoted to Pending only on
//!   acceptance or positive presence, never on absence or contested evidence.
//! - `Mined` needs an independent pair of operator-labelled sources agreeing on
//!   block and height; one operator yields `MinedSingleSource`, which resolves
//!   the record for a new review and later legs but never says the source may
//!   be discarded. Discarding also needs [`MIN_DISCARD_CONFIRMATIONS`]. A
//!   mined record is demoted only by a positive reorg, absence, or mempool
//!   observation; unavailable or contested evidence leaves it mined.
//! - `Expired` needs one labelled source reporting absence past the expiry
//!   height plus [`EXPIRY_MARGIN_BLOCKS`]; an expiry height of 0 never expires.
//! - A rejected new transition appends nothing, so invalid input cannot poison
//!   the journal; replay of older event shapes stays conservative.

mod lifecycle;
mod log;
mod observation;
mod submission;

pub use crate::models::TxLifecycleState;
pub(crate) use lifecycle::validate_transition;
pub use log::*;
pub use observation::*;
pub use submission::*;

#[cfg(test)]
mod tests;
