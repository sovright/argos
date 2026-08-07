//! Direct Zcash peer-to-peer access, for the one job lightwalletd cannot do.
//!
//! Sprout notes live in JoinSplits, and JoinSplits are absent from the
//! lightwalletd protocol entirely — compact blocks carry Sapling and Orchard
//! outputs only, and `TreeState` has a `saplingTree` and an `orchardTree`
//! field and no Sprout equivalent. So a wallet holding a bare Sprout
//! spending key, with no `wallet.dat` note metadata and no cached witness,
//! cannot be recovered through a light client at all. This module reads full
//! blocks from the network to close that gap.
//!
//! # Why not just require a full node
//!
//! Because the people this helps are, by construction, holding funds they
//! have already had trouble reaching. Requiring a multi-hundred-gigabyte
//! node as a precondition would exclude most of them. Speaking the p2p
//! protocol keeps the tool self-contained.
//!
//! # Bounded by ZIP 211
//!
//! Adding value to the Sprout pool is disabled from Canopy onward, so every
//! Sprout note that can exist was created below that height. The scan range
//! is closed and never grows, which is what makes a from-genesis historical
//! sweep tractable here where it would not be for Sapling or Orchard.

pub mod peer;
pub mod wire;
