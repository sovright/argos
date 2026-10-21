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
//!
//! Before returning any JoinSplits, this module checks every transaction ID
//! and its order against the header's `hashMerkleRoot`. Sprout JoinSplits are
//! v2-v4 effecting data committed by their legacy transaction IDs. NU5+
//! authorizing data has a separate auth-data/block-commitment boundary; this
//! helper is not a full modern consensus block verifier.

use argos_wallet_import::keys::SproutJoinSplit;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use super::wire::{read_compact_size, sha256d};

/// Fixed part of a Zcash block header, before the Equihash solution.
const HEADER_FIXED_LEN: usize = 140;
const MERKLE_ROOT_RANGE: std::ops::Range<usize> = 36..68;

/// Groth16 JoinSplit proofs are used from transaction version 4 onward;
/// earlier versions carry the larger PHGR13 proof. The two serializations
/// differ in length, so the reader must be told which.
const SAPLING_TX_VERSION: u32 = 4;

#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    #[error("block is truncated or malformed")]
    Malformed,
    #[error("a block must contain at least its coinbase transaction")]
    NoTransactions,
    #[error("a block has {bytes} undeclared trailing bytes after its transactions")]
    TrailingData { bytes: usize },
    #[error("the block transaction Merkle tree is mutated by a duplicated sibling pair")]
    MutatedMerkleTree,
    #[error("the block transaction Merkle root does not match its header")]
    MerkleRootMismatch,
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
    if tx_count == 0 {
        return Err(BlockError::NoTransactions);
    }

    let mut out = Vec::new();
    let mut txids = Vec::new();
    for index in 0..tx_count as usize {
        let rest = block.get(pos..).ok_or(BlockError::Malformed)?;

        let mut cursor = std::io::Cursor::new(rest);
        let tx = Transaction::read(&mut cursor, branch_id)
            .map_err(|source| BlockError::Transaction { index, source })?;
        let consumed = cursor.position() as usize;
        pos = pos.checked_add(consumed).ok_or(BlockError::Malformed)?;

        let txid: [u8; 32] = tx.txid().as_ref()[..]
            .try_into()
            .map_err(|_| BlockError::Malformed)?;
        txids.push(txid);

        let Some(bundle) = tx.sprout_bundle() else {
            continue;
        };

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

    if pos != block.len() {
        let bytes = block.len().checked_sub(pos).ok_or(BlockError::Malformed)?;
        return Err(BlockError::TrailingData { bytes });
    }
    if transaction_merkle_root(&txids)? != header_merkle_root(block)? {
        return Err(BlockError::MerkleRootMismatch);
    }

    Ok(out)
}

fn header_merkle_root(block: &[u8]) -> Result<[u8; 32], BlockError> {
    block
        .get(MERKLE_ROOT_RANGE)
        .ok_or(BlockError::Malformed)?
        .try_into()
        .map_err(|_| BlockError::Malformed)
}

/// The Bitcoin-style transaction Merkle root zcashd commits to in
/// `hashMerkleRoot`, refusing the duplicated-sibling mutation
/// (CVE-2012-2459).
///
/// # The 64-byte inner-node ambiguity
///
/// An inner node is the double SHA-256 of 64 bytes — two child hashes — and
/// a transaction that is exactly 64 bytes long hashes the same way. A body
/// that replaced two sibling transactions with one "transaction" whose bytes
/// are their two txids would therefore reproduce the root. That is not
/// exploitable by a peer here: the 64 bytes are hashes fixed by the
/// authenticated header's history, not chosen by the peer, and they must
/// also parse under `Transaction::read` as a complete transaction consuming
/// exactly those 64 bytes — a valid version and version group, consistent
/// counts — which fixed hash output cannot be ground into. Even if it did
/// parse, the effect would be to drop the two real transactions, never to
/// inject chosen JoinSplit data. A peer that could grind txids would have to
/// mine its own proof-of-work chain, which the checkpoints and the
/// lightwalletd `TipAnchor` bound, and past which T-N7 already documents
/// that the scan rests on the peer.
fn transaction_merkle_root(txids: &[[u8; 32]]) -> Result<[u8; 32], BlockError> {
    if txids.is_empty() {
        return Err(BlockError::NoTransactions);
    }

    let mut level = txids.to_vec();
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            if pair.len() == 2 && pair[0] == pair[1] {
                return Err(BlockError::MutatedMerkleTree);
            }
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&pair[0]);
            combined[32..].copy_from_slice(pair.get(1).unwrap_or(&pair[0]));
            next.push(sha256d(&combined));
        }
        level = next;
    }
    Ok(level[0])
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

/// Hand-built blocks for tests here and in the scan runner: a valid
/// transaction list under a header whose `hashMerkleRoot` commits to it.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{HEADER_FIXED_LEN, MERKLE_ROOT_RANGE};
    use crate::p2p::wire::{sha256d, write_compact_size};

    /// A minimal Sprout v2 coinbase-shaped transaction, distinct per `tag`.
    pub(crate) fn legacy_test_transaction(tag: u8) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&2u32.to_le_bytes()); // Sprout v2
        tx.push(1); // one input
        tx.extend_from_slice(&[0; 32]); // previous txid
        tx.extend_from_slice(&u32::MAX.to_le_bytes()); // previous index
        tx.push(1); // script length
        tx.push(tag);
        tx.extend_from_slice(&u32::MAX.to_le_bytes()); // sequence
        tx.push(1); // one output
        tx.extend_from_slice(&0i64.to_le_bytes()); // value
        tx.push(0); // empty output script
        tx.extend_from_slice(&0u32.to_le_bytes()); // lock time
        tx.push(0); // empty JoinSplit vector
        tx
    }

    /// The Bitcoin-style Merkle root, written independently of the
    /// production code (no mutation check), for building headers.
    pub(crate) fn reference_merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
        let mut level = txids.to_vec();
        if level.is_empty() {
            return [0; 32];
        }
        while level.len() > 1 {
            let mut next = Vec::new();
            for pair in level.chunks(2) {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&pair[0]);
                combined[32..].copy_from_slice(pair.get(1).unwrap_or(&pair[0]));
                next.push(sha256d(&combined));
            }
            level = next;
        }
        level[0]
    }

    /// A block with an empty Equihash solution whose header commits to
    /// exactly `transactions`.
    pub(crate) fn test_block(transactions: &[Vec<u8>]) -> Vec<u8> {
        let txids: Vec<[u8; 32]> = transactions.iter().map(|tx| sha256d(tx)).collect();
        let mut block = vec![0u8; HEADER_FIXED_LEN];
        block[MERKLE_ROOT_RANGE].copy_from_slice(&reference_merkle_root(&txids));
        block.push(0); // empty Equihash solution
        write_compact_size(&mut block, transactions.len() as u64);
        for tx in transactions {
            block.extend_from_slice(tx);
        }
        block
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{legacy_test_transaction, reference_merkle_root, test_block};
    use super::*;

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("valid hex")
            })
            .collect()
    }

    /// A real mainnet block, pinned byte for byte.
    ///
    /// Fetched on 2026-10-21 from the Blockchair API,
    /// `https://api.blockchair.com/zcash/raw/block/<height>` (`raw_block`,
    /// with the explorer's `decoded_raw_block.tx` for the txids). Every
    /// value is in explorer display order (byte-reversed). The bytes check
    /// themselves: the header's double SHA-256 must be the published block
    /// hash, and that header must carry valid mainnet proof of work, so a
    /// corrupted fixture cannot pass as real.
    struct RealBlock {
        height: u32,
        bytes: &'static [u8],
        hash: &'static str,
        merkle_root: &'static str,
        txids: &'static [&'static str],
    }

    /// Odd transaction count (3): the last txid is paired with itself.
    const MAINNET_452: RealBlock = RealBlock {
        height: 452,
        bytes: include_bytes!("testdata/mainnet-block-452.bin"),
        hash: "00000035e8c77a3238088ec78b35454cd43985f0ddb6a7cc2d6094c652e75e55",
        merkle_root: "10dfad86b6845674712b11c2905babaf4393234aa936d393d32e3a31fb312171",
        txids: &[
            "0ee57d194663bbba14d9d828de00c21c4c1b72c4f368e1ce256394fe56aeffb5",
            "a32ab2d594ba1bc68ad3f4d7208b6abfac8059fc1308dffac281167d8ae359c6",
            "ea82f6992f92a3a29fbe90a4b920278beb43eea8d7c021b2d6fb9fffec995dab",
        ],
    };

    /// Even transaction count (4): two full levels, no self-pairing.
    const MAINNET_464: RealBlock = RealBlock {
        height: 464,
        bytes: include_bytes!("testdata/mainnet-block-464.bin"),
        hash: "0000006ff2f6862ef99905be7fcbdeeff246201a1215f311202283e9b123373d",
        merkle_root: "f0113965c77321ef08da778c4cd38d8be63f21439714654dd42c49c9dd219979",
        txids: &[
            "75a52a987a198910182046eac20f2775dd8af41ab3d30ff90c0422cd6eb28b3f",
            "5d16df2c6e11f01c50bd6651aed258a8bd42e30d6535ec076fbd322e97af3cc0",
            "a232b009eaae4c1971253a518be04c2de785af08b761a25f7bbcda189ada1ca7",
            "831b5fa2c10cabdd2677578de9ac0b9903baaa6d695100d96b68febe7fa71539",
        ],
    };

    /// Display order (as explorers print hashes) to wire order.
    fn wire_order(display: &str) -> [u8; 32] {
        let mut bytes: [u8; 32] = decode_hex(display).try_into().expect("32 bytes");
        bytes.reverse();
        bytes
    }

    /// The fixture is the real block: its header hashes to the published
    /// block hash and carries valid mainnet proof of work.
    fn assert_genuine(block: &RealBlock) {
        let header_end = skip_block_header(block.bytes).expect("header");
        let hash = block_hash(block.bytes).expect("hash");
        assert_eq!(hash, wire_order(block.hash), "block {}", block.height);
        let header = crate::p2p::wire::BlockHeader {
            hash,
            prev_hash: block.bytes[4..36].try_into().unwrap(),
            raw: block.bytes[..header_end].to_vec(),
        };
        crate::p2p::wire::verify_header_pow(crate::p2p::wire::P2pNetwork::Mainnet, &header)
            .unwrap_or_else(|err| panic!("block {}: {err:?}", block.height));
        assert_eq!(
            header_merkle_root(block.bytes).unwrap(),
            wire_order(block.merkle_root),
            "block {}",
            block.height
        );
    }

    /// Review of #265: the Merkle tests compared production against a copy
    /// of itself, so a shared mistake in pairing or byte order would pass.
    /// These are real mainnet blocks whose roots were computed by zcashd.
    #[test]
    fn real_mainnet_txids_reproduce_the_header_merkle_root() {
        assert_eq!(MAINNET_452.txids.len() % 2, 1, "an odd count");
        assert_eq!(MAINNET_464.txids.len() % 2, 0, "an even count");
        for block in [&MAINNET_452, &MAINNET_464] {
            assert_genuine(block);
            let txids: Vec<[u8; 32]> = block.txids.iter().map(|t| wire_order(t)).collect();
            assert_eq!(
                transaction_merkle_root(&txids).unwrap(),
                header_merkle_root(block.bytes).unwrap(),
                "block {}",
                block.height
            );
        }
    }

    /// The whole path on real bytes: every transaction parsed, its txid
    /// derived by upstream, and the root checked against the header.
    #[test]
    fn real_mainnet_blocks_authenticate_end_to_end() {
        for block in [&MAINNET_452, &MAINNET_464] {
            assert_genuine(block);
            let result = joinsplits_in_block(block.bytes, BranchId::Canopy);
            assert!(result.is_ok(), "block {}: {result:?}", block.height);

            // One flipped bit in the last transaction's body breaks it.
            let mut tampered = block.bytes.to_vec();
            let last = tampered.len() - 5; // inside the final transaction
            tampered[last] ^= 1;
            assert!(
                matches!(
                    joinsplits_in_block(&tampered, BranchId::Canopy),
                    Err(BlockError::MerkleRootMismatch)
                ),
                "block {}",
                block.height
            );
        }
    }

    #[test]
    fn zero_transaction_body_is_rejected() {
        let block = test_block(&[]);
        assert!(matches!(
            joinsplits_in_block(&block, BranchId::Canopy),
            Err(BlockError::NoTransactions)
        ));
    }

    #[test]
    fn declared_transactions_must_consume_the_entire_body() {
        let mut block = test_block(&[legacy_test_transaction(1)]);
        block.push(0xAA);
        assert!(matches!(
            joinsplits_in_block(&block, BranchId::Canopy),
            Err(BlockError::TrailingData { bytes: 1 })
        ));
    }

    #[test]
    fn transaction_merkle_root_binds_omission_substitution_and_order() {
        let transactions: Vec<_> = (1..=3).map(legacy_test_transaction).collect();
        let original = test_block(&transactions);
        assert!(joinsplits_in_block(&original, BranchId::Canopy).is_ok());

        let modified_bodies = [
            vec![transactions[0].clone(), transactions[1].clone()],
            vec![
                transactions[0].clone(),
                legacy_test_transaction(4),
                transactions[2].clone(),
            ],
            vec![
                transactions[0].clone(),
                transactions[2].clone(),
                transactions[1].clone(),
            ],
        ];
        for body in modified_bodies {
            let mut block = original[..HEADER_FIXED_LEN + 1].to_vec();
            super::super::wire::write_compact_size(&mut block, body.len() as u64);
            for tx in body {
                block.extend_from_slice(&tx);
            }
            assert!(matches!(
                joinsplits_in_block(&block, BranchId::Canopy),
                Err(BlockError::MerkleRootMismatch)
            ));
        }
    }

    #[test]
    fn duplicate_last_transaction_is_rejected_as_a_mutated_merkle_tree() {
        let transactions: Vec<_> = (1..=3).map(legacy_test_transaction).collect();
        let txids: Vec<_> = transactions.iter().map(|tx| sha256d(tx)).collect();
        let mut duplicated_txids = txids.clone();
        duplicated_txids.push(txids[2]);
        assert_eq!(
            reference_merkle_root(&txids),
            reference_merkle_root(&duplicated_txids)
        );

        let original = test_block(&transactions);
        let mut mutated = original[..HEADER_FIXED_LEN + 1].to_vec();
        super::super::wire::write_compact_size(&mut mutated, 4);
        for tx in &transactions {
            mutated.extend_from_slice(tx);
        }
        mutated.extend_from_slice(&transactions[2]);
        assert!(matches!(
            joinsplits_in_block(&mutated, BranchId::Canopy),
            Err(BlockError::MutatedMerkleTree)
        ));
    }

    #[test]
    fn zip244_txid_is_used_for_v5_block_merkle_root() {
        // Zebra v6.2.0 mainnet getblocktemplate coinbase snapshot, recorded independently.
        const V5_COINBASE_HEX: [&str; 7] = [
            "050000800a27a726b4d0d6c20000000041be1900010000000000000000000000",
            "000000000000000000000000000000000000000000ffffffff090341be1904f0",
            "9fa693ffffffff0480b2e60e0000000017a9147e7e7e7e7e7e7e7e7e7e7e7e7e",
            "7e7e7e7e7e7e7e87286bee000000000017a914d45cb1adffb5215a42720532a0",
            "76f02c7c778c908738c94d010000000017a91469a9f95a98fe581b6eb52841ef",
            "4806dc4402eb908740787d010000000017a914931fec54c1fea86e574462cc32",
            "013f5400b8912987000000",
        ];
        let coinbase = decode_hex(&V5_COINBASE_HEX.concat());
        let zip244_display =
            decode_hex("0dd4c87d6aba52431fef01079578826b547a22e444af986368c507918f893e8a");
        let sha256d_display =
            decode_hex("f96ec1f0b0b8732dc3fc81bc629bfe6ef437d704f03ef884359ddcb7044f0613");
        assert_ne!(zip244_display, sha256d_display);

        let mut block = test_block(&[coinbase]);
        block[MERKLE_ROOT_RANGE].copy_from_slice(&zip244_display.iter().rev().copied().collect::<Vec<_>>());
        let result = joinsplits_in_block(&block, BranchId::Nu5);
        assert!(result.is_ok(), "v5 coinbase should parse: {result:?}");

        block[MERKLE_ROOT_RANGE].copy_from_slice(&sha256d_display.iter().rev().copied().collect::<Vec<_>>());
        assert!(matches!(
            joinsplits_in_block(&block, BranchId::Nu5),
            Err(BlockError::MerkleRootMismatch)
        ));
    }

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

    /// A peer can claim any transaction count; no vector reserves capacity
    /// from hostile `tx_count`.
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
