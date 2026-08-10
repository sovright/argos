//! Pulling JoinSplits out of a full block.
//!
//! # Why upstream parses the transactions
//!
//! Transaction serialization has changed shape repeatedly — v1 through v5,
//! Overwinter's version group ids, the Sapling bundle, NU5's rewrite — and a
//! hand-rolled parser for all of it would be a large, silent-failure-prone
//! surface over bytes an anonymous peer supplied. `zcash_primitives` already
//! parses every version correctly, so it does that job here.
//!
//! What it will not do is hand back a JoinSplit's `ephemeral_key` or its
//! `ciphertexts`: `JsDescription` exposes accessors for `anchor`,
//! `nullifiers`, `commitments` and `random_seed`, and those two fields have
//! none. They are exactly the two decryption needs.
//!
//! `JsDescription::write` is public, so each JoinSplit is serialized back out
//! and read with the same field reader the wallet importer uses. That keeps
//! one parser for a structure with one serialization, rather than a second
//! copy that could drift, and it means upstream still owns all the version
//! handling.

use argos_wallet_import::keys::SproutJoinSplit;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use super::wire::{read_compact_size, sha256d};

/// Fixed part of a Zcash block header, before the Equihash solution.
const HEADER_FIXED_LEN: usize = 140;

/// Groth16 JoinSplit proofs are used from transaction version 4 onward;
/// earlier versions carry the larger PHGR13 proof. The two serializations
/// differ in length, so the reader must be told which.
const SAPLING_TX_VERSION: u32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    #[error("block is truncated or malformed")]
    Malformed,
    #[error("transaction {index} in this block could not be parsed: {source}")]
    Transaction {
        index: usize,
        #[source]
        source: std::io::Error,
    },
    #[error("a JoinSplit in transaction {txid} could not be re-read after serialization")]
    JoinSplitUnreadable { txid: String },
}

/// Every JoinSplit in a block, in the order consensus appends them to the
/// Sprout commitment tree.
///
/// Order is not cosmetic: a note's witness is its position in that tree, so a
/// scanner that appends commitments in the wrong order derives a witness that
/// authenticates nothing and produces a proof the network rejects.
pub fn joinsplits_in_block(
    block: &[u8],
    branch_id: BranchId,
) -> Result<Vec<SproutJoinSplit>, BlockError> {
    let mut pos = skip_block_header(block)?;

    let (tx_count, used) = read_compact_size(block.get(pos..).ok_or(BlockError::Malformed)?)
        .ok_or(BlockError::Malformed)?;
    pos = pos.checked_add(used).ok_or(BlockError::Malformed)?;

    // A block cannot hold more transactions than it has bytes for, so a
    // count that could not possibly fit is rejected before it sizes anything.
    if tx_count > block.len() as u64 {
        return Err(BlockError::Malformed);
    }

    let mut out = Vec::new();
    for index in 0..tx_count as usize {
        let rest = block.get(pos..).ok_or(BlockError::Malformed)?;

        let mut cursor = std::io::Cursor::new(rest);
        let tx = Transaction::read(&mut cursor, branch_id)
            .map_err(|source| BlockError::Transaction { index, source })?;
        let consumed = cursor.position() as usize;
        pos = pos.checked_add(consumed).ok_or(BlockError::Malformed)?;

        let Some(bundle) = tx.sprout_bundle() else {
            continue;
        };

        let txid: [u8; 32] = tx.txid().as_ref()[..]
            .try_into()
            .map_err(|_| BlockError::Malformed)?;

        // The version that produced this transaction decides the proof
        // encoding, and so how long each JoinSplit is on the wire.
        let use_groth = (tx.version().header() & 0x7FFF_FFFF) >= SAPLING_TX_VERSION;

        for (js_index, js) in bundle.joinsplits.iter().enumerate() {
            let mut bytes = Vec::new();
            js.write(&mut bytes)
                .map_err(|_| BlockError::JoinSplitUnreadable { txid: hex(&txid) })?;

            let mut parsed = argos_wallet_import::zcashd::sprout::parse_js_description(
                &bytes,
                use_groth,
                txid,
                js_index as u64,
            )
            .ok_or_else(|| BlockError::JoinSplitUnreadable { txid: hex(&txid) })?;

            // Serialized once per transaction, after the vector, so it is
            // not part of any single description.
            parsed.joinsplit_pubkey = bundle.joinsplit_pubkey;
            out.push(parsed);
        }
    }

    Ok(out)
}

/// The block's own hash, for chaining and progress reporting.
pub fn block_hash(block: &[u8]) -> Result<[u8; 32], BlockError> {
    let end = skip_block_header(block)?;
    Ok(sha256d(block.get(..end).ok_or(BlockError::Malformed)?))
}

/// Advance past the header, returning where the transaction count begins.
fn skip_block_header(block: &[u8]) -> Result<usize, BlockError> {
    let after_fixed = block.get(HEADER_FIXED_LEN..).ok_or(BlockError::Malformed)?;
    let (solution_len, used) = read_compact_size(after_fixed).ok_or(BlockError::Malformed)?;
    let solution_len = usize::try_from(solution_len).map_err(|_| BlockError::Malformed)?;

    let end = HEADER_FIXED_LEN
        .checked_add(used)
        .and_then(|v| v.checked_add(solution_len))
        .ok_or(BlockError::Malformed)?;
    if end > block.len() {
        return Err(BlockError::Malformed);
    }
    Ok(end)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A block with no transactions at all is malformed — every block has at
    /// least a coinbase — but it must be reported, not panicked on.
    #[test]
    fn a_truncated_block_is_rejected() {
        // Shorter than the fixed header: neither function can do anything.
        for len in [0, 10, HEADER_FIXED_LEN] {
            let block = vec![0u8; len];
            assert!(
                joinsplits_in_block(&block, BranchId::Nu5).is_err(),
                "a {len}-byte block must not yield joinsplits"
            );
            assert!(
                block_hash(&block).is_err(),
                "a {len}-byte block must not yield a hash"
            );
        }

        // Exactly the header plus an empty solution length. This *is* a
        // structurally complete header, so hashing it succeeds — the two
        // functions have different contracts, which an earlier `a || b`
        // assertion hid. What must still fail is reading transactions,
        // because there is no transaction count.
        let mut header_only = vec![0u8; HEADER_FIXED_LEN];
        header_only.push(0x00);
        assert!(
            block_hash(&header_only).is_ok(),
            "a complete header hashes even with no body after it"
        );
        assert!(
            joinsplits_in_block(&header_only, BranchId::Nu5).is_err(),
            "a block with no transaction count must not parse"
        );
    }

    /// A peer can claim any transaction count; it must not size anything.
    #[test]
    fn a_lying_transaction_count_is_rejected() {
        let mut block = vec![0u8; HEADER_FIXED_LEN];
        block.push(0x00); // empty solution
        block.push(0xFF); // CompactSize: 8-byte count follows
        block.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(
            joinsplits_in_block(&block, BranchId::Nu5),
            Err(BlockError::Malformed)
        ));
    }

    /// The header walk has to respect the solution length rather than assume
    /// the mainnet size, or every regtest block would be misparsed.
    #[test]
    fn the_header_walk_follows_the_solution_length() {
        for solution_len in [0usize, 32, 1344] {
            let mut block = vec![0u8; HEADER_FIXED_LEN];
            super::super::wire::write_compact_size(&mut block, solution_len as u64);
            block.extend_from_slice(&vec![0xAB; solution_len]);
            let header_end = block.len();
            block.push(0x00); // zero transactions

            assert_eq!(
                skip_block_header(&block).expect("must walk"),
                header_end,
                "solution length {solution_len} must be honoured"
            );
            // The hash covers exactly the header, solution included.
            assert_eq!(block_hash(&block).unwrap(), sha256d(&block[..header_end]));
        }
    }

    /// A block whose header is fine but whose transaction bytes are garbage
    /// must name the transaction rather than fail anonymously.
    #[test]
    fn a_bad_transaction_is_reported_with_its_index() {
        let mut block = vec![0u8; HEADER_FIXED_LEN];
        block.push(0x00); // empty solution
        block.push(0x01); // one transaction
        block.extend_from_slice(&[0xFF; 8]); // not a transaction

        match joinsplits_in_block(&block, BranchId::Nu5) {
            Err(BlockError::Transaction { index, .. }) => assert_eq!(index, 0),
            other => panic!("expected a transaction error, got {other:?}"),
        }
    }
}
