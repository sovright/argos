//! The Sprout pack: every JoinSplit on the chain, without the rest of it.
//!
//! # Why this exists
//!
//! A Sprout scan has to read every JoinSplit ever mined, and until now the
//! only way to get them was to download every full block from the p2p
//! network — hundreds of gigabytes, over peers that refuse most inbound
//! connections. The scanner itself reads a small fraction of that: the
//! fields of a [`SproutJoinSplit`]. A pack is those fields, block by block,
//! from height 1 to a fixed end height, written once by a maintainer who has
//! a synced node and shipped to everyone who does not.
//!
//! After the pack, the scan continues over p2p from the pack's last block to
//! the tip exactly as before. The pack never ends the scan: Sprout
//! JoinSplits continue after Canopy, so the walk still has to reach the tip.
//!
//! # Layout
//!
//! A pack is a directory holding [`MANIFEST_FILE`] and one file per chunk
//! ([`chunk_file_name`]). Chunk `i` covers heights `i * CHUNK_BLOCKS + 1`
//! through `(i + 1) * CHUNK_BLOCKS`, the last chunk ending at the pack's end
//! height. Fixed boundaries keep two builds of the same chain byte-identical,
//! and keep every chunk well under GitHub's 2 GiB release-asset limit.
//!
//! Every block appears, including the many with no JoinSplits, as its hash
//! and a zero count. That costs 36 bytes a block and buys two things: the
//! scanner sees exactly the contiguous heights a p2p walk feeds it, so its
//! rollback history and checkpoints are indistinguishable from a p2p scan's,
//! and every pinned checkpoint hash in [`crate::p2p::wire`] is checked
//! against the pack as it is read.
//!
//! All integers are little-endian and fixed width. There is no compression
//! (the ciphertexts that make up most of the bytes do not compress) and no
//! timestamp, so the bytes are a pure function of the chain.
//!
//! # Trust
//!
//! A pack carries no headers, so unlike a p2p walk it cannot prove its own
//! contents. What stands behind it is the SHA-256 of its manifest, pinned in
//! [`PINNED_PACKS`] for the release that ships it. The manifest in turn pins
//! every chunk's SHA-256, its last block hash and the Sprout commitment tree
//! root at the end height. A maintainer builds the pack from their own node,
//! a second builds it independently, and the two manifest hashes must match
//! before one is pinned.
//!
//! On mainnet only a pinned pack is accepted: a pack feeds the spent-note
//! evidence the wallet-file sweep relies on, and a wrong one could hide a
//! live note, which is worse than a phantom balance. Testnet and regtest
//! have no pinned checkpoints either and accept any well-formed pack.
//!
//! The hand-off is checked too. The scan resumes p2p from the pack's last
//! block hash, and the existing cursor reconciliation asks live peers to
//! confirm that hash is on the current chain before a single later block is
//! read.

use std::{
    fs,
    io::{self, BufReader, Read, Write},
    path::{Path, PathBuf},
};

use argos_wallet_import::keys::SproutJoinSplit;
use sha2::{Digest, Sha256};

use crate::{
    error::{ZeckError, ZeckResult},
    p2p::wire::P2pNetwork,
};

/// The manifest's file name inside a pack directory.
pub const MANIFEST_FILE: &str = "manifest.bin";

/// Blocks per chunk. Part of the format: changing it changes every hash.
pub const CHUNK_BLOCKS: u32 = 100_000;

/// The format version written into the manifest and every chunk.
pub const PACK_FORMAT_VERSION: u8 = 1;

/// How far below the tip a pack must end, at build time.
///
/// A pack is pinned forever, so its last block must never be reorganized
/// away. Ten times the scanner's own rollback window.
pub const PACK_MIN_DEPTH: u32 = 1_000;

const MANIFEST_MAGIC: &[u8; 8] = b"ARGOSSPM";
const CHUNK_MAGIC: &[u8; 8] = b"ARGOSSPC";

/// A manifest larger than this is not one: even a pack to height 100 million
/// has a thousand chunks at 92 bytes each.
const MAX_MANIFEST_BYTES: u64 = 1 << 20;

/// Size of one JoinSplit's note ciphertext (`ZC_NOTECIPHERTEXT_SIZE`).
const CIPHERTEXT_LEN: usize = 601;

/// A count larger than this in a single block is malformed. A 2 MB block
/// holds at most ~1,100 JoinSplits; this only bounds an allocation.
const MAX_JOINSPLITS_PER_BLOCK: u32 = 4_096;

/// Bytes of one encoded JoinSplit record.
pub const JOINSPLIT_RECORD_LEN: usize = 32 + 8 + 32 + 64 + 64 + 32 + 32 + 32 + 2 * CIPHERTEXT_LEN;

const MANIFEST_ENTRY_LEN: usize = 4 + 4 + 32 + 8 + 8 + 32;

/// A pack whose manifest hash is pinned for a network.
pub struct PinnedPack {
    pub network: P2pNetwork,
    /// SHA-256 of the manifest file, lowercase hex.
    pub manifest_sha256: &'static str,
    pub end_height: u32,
}

/// The packs this release vouches for.
///
/// See `docs/sprout-pack.md` for the release procedure. A mainnet scan
/// refuses any pack not listed here and walks the chain over p2p instead.
///
/// Mainnet, blocks 1 to 3,500,000: built twice on 2026-10-28 from two
/// Zebra 7.0.0 nodes in different regions (us-east4 and europe-west4), and
/// both builds produced this manifest hash. End block hash
/// `000000000008a15f5db2c10ddec496dd3466f624cbb5100e09497e7addbfb531`,
/// Sprout tree root
/// `0f68d989a0a2b6d5608b7bc18507c4b2c32125cb10b864cd18019faf5ac9213d`,
/// 773,651 JoinSplits.
pub const PINNED_PACKS: &[PinnedPack] = &[PinnedPack {
    network: P2pNetwork::Mainnet,
    manifest_sha256: "805435e69ae7a28c2045abcb5fa7b049de7e4c288f1f7c3d8d9529eb143ba57d",
    end_height: 3500000,
}];

/// One chunk, as the manifest describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEntry {
    pub first_height: u32,
    pub last_height: u32,
    /// Hash of the block at `last_height`, in wire order.
    pub last_hash: [u8; 32],
    pub joinsplits: u64,
    pub byte_len: u64,
    pub sha256: [u8; 32],
}

/// The table of contents of a pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackManifest {
    pub network: P2pNetwork,
    pub end_height: u32,
    /// Hash of the block at `end_height`, in wire order.
    pub end_hash: [u8; 32],
    /// The Sprout commitment tree root after the block at `end_height`.
    pub sprout_root: [u8; 32],
    pub total_joinsplits: u64,
    pub chunks: Vec<ChunkEntry>,
}

/// One block as a pack stores it.
#[derive(Debug, Clone)]
pub struct PackBlock {
    pub height: u32,
    pub hash: [u8; 32],
    pub joinsplits: Vec<SproutJoinSplit>,
}

fn pack_error(message: impl Into<String>) -> ZeckError {
    ZeckError::InvalidConfig(format!("Sprout pack: {}", message.into()))
}

fn io_error(path: &Path, err: io::Error) -> ZeckError {
    pack_error(format!("{}: {err}", path.display()))
}

fn network_tag(network: P2pNetwork) -> u8 {
    match network {
        P2pNetwork::Mainnet => 0,
        P2pNetwork::Testnet => 1,
        P2pNetwork::Regtest => 2,
    }
}

fn network_from_tag(tag: u8) -> Option<P2pNetwork> {
    match tag {
        0 => Some(P2pNetwork::Mainnet),
        1 => Some(P2pNetwork::Testnet),
        2 => Some(P2pNetwork::Regtest),
        _ => None,
    }
}

fn network_name(network: P2pNetwork) -> &'static str {
    match network {
        P2pNetwork::Mainnet => "mainnet",
        P2pNetwork::Testnet => "testnet",
        P2pNetwork::Regtest => "regtest",
    }
}

/// The file name of chunk `index`.
pub fn chunk_file_name(index: usize) -> String {
    format!("chunk-{index:04}.bin")
}

/// The height range chunk `index` covers in a pack ending at `end_height`,
/// or `None` past the last chunk.
pub fn chunk_range(index: usize, end_height: u32) -> Option<(u32, u32)> {
    let index = u32::try_from(index).ok()?;
    let first = index.checked_mul(CHUNK_BLOCKS)?.checked_add(1)?;
    if first > end_height {
        return None;
    }
    let last = index
        .checked_add(1)?
        .checked_mul(CHUNK_BLOCKS)
        .map_or(end_height, |last| last.min(end_height));
    Some((first, last))
}

/// Number of chunks in a pack ending at `end_height`.
pub fn chunk_count(end_height: u32) -> usize {
    end_height.div_ceil(CHUNK_BLOCKS) as usize
}

/// Lowercase hex, for printing hashes.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

// ─── Manifest ──────────────────────────────────────────────────────────────

impl PackManifest {
    /// The canonical encoding. Its SHA-256 is what gets pinned.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + self.chunks.len() * MANIFEST_ENTRY_LEN);
        out.extend_from_slice(MANIFEST_MAGIC);
        out.push(PACK_FORMAT_VERSION);
        out.push(network_tag(self.network));
        out.extend_from_slice(&CHUNK_BLOCKS.to_le_bytes());
        out.extend_from_slice(&self.end_height.to_le_bytes());
        out.extend_from_slice(&self.end_hash);
        out.extend_from_slice(&self.sprout_root);
        out.extend_from_slice(&self.total_joinsplits.to_le_bytes());
        out.extend_from_slice(&(self.chunks.len() as u32).to_le_bytes());
        for chunk in &self.chunks {
            out.extend_from_slice(&chunk.first_height.to_le_bytes());
            out.extend_from_slice(&chunk.last_height.to_le_bytes());
            out.extend_from_slice(&chunk.last_hash);
            out.extend_from_slice(&chunk.joinsplits.to_le_bytes());
            out.extend_from_slice(&chunk.byte_len.to_le_bytes());
            out.extend_from_slice(&chunk.sha256);
        }
        out
    }

    /// Parse and check a manifest's internal consistency.
    ///
    /// Strict on purpose: the chunk table must be exactly the fixed
    /// boundaries for the end height, the counts must add up, and nothing
    /// may trail. A manifest that parses is one the reader can follow
    /// without a second guess.
    pub fn from_bytes(bytes: &[u8]) -> ZeckResult<Self> {
        let mut r = Cursor { bytes, pos: 0 };
        let bad = |what: &str| pack_error(format!("the manifest is malformed ({what})"));
        if r.take(8).ok_or_else(|| bad("truncated"))? != MANIFEST_MAGIC {
            return Err(bad("not a Sprout pack manifest"));
        }
        let version = r.u8().ok_or_else(|| bad("truncated"))?;
        if version != PACK_FORMAT_VERSION {
            return Err(pack_error(format!(
                "the manifest is format version {version}; this Argos reads version \
                 {PACK_FORMAT_VERSION}"
            )));
        }
        let network = r
            .u8()
            .and_then(network_from_tag)
            .ok_or_else(|| bad("unknown network"))?;
        let chunk_blocks = r.u32().ok_or_else(|| bad("truncated"))?;
        if chunk_blocks != CHUNK_BLOCKS {
            return Err(bad("unexpected chunk size"));
        }
        let end_height = r.u32().ok_or_else(|| bad("truncated"))?;
        let end_hash = r.array32().ok_or_else(|| bad("truncated"))?;
        let sprout_root = r.array32().ok_or_else(|| bad("truncated"))?;
        let total_joinsplits = r.u64().ok_or_else(|| bad("truncated"))?;
        let count = r.u32().ok_or_else(|| bad("truncated"))? as usize;
        if end_height == 0 || count != chunk_count(end_height) {
            return Err(bad("the chunk table does not match the end height"));
        }
        let mut chunks = Vec::with_capacity(count);
        let mut sum = 0u64;
        for index in 0..count {
            let entry = ChunkEntry {
                first_height: r.u32().ok_or_else(|| bad("truncated"))?,
                last_height: r.u32().ok_or_else(|| bad("truncated"))?,
                last_hash: r.array32().ok_or_else(|| bad("truncated"))?,
                joinsplits: r.u64().ok_or_else(|| bad("truncated"))?,
                byte_len: r.u64().ok_or_else(|| bad("truncated"))?,
                sha256: r.array32().ok_or_else(|| bad("truncated"))?,
            };
            if chunk_range(index, end_height) != Some((entry.first_height, entry.last_height)) {
                return Err(bad("a chunk does not sit on its fixed boundary"));
            }
            sum = sum
                .checked_add(entry.joinsplits)
                .ok_or_else(|| bad("JoinSplit count overflows"))?;
            chunks.push(entry);
        }
        if r.pos != bytes.len() {
            return Err(bad("trailing bytes"));
        }
        if sum != total_joinsplits {
            return Err(bad("the chunk JoinSplit counts do not add up"));
        }
        if chunks.last().map(|c| c.last_hash) != Some(end_hash) {
            return Err(bad("the last chunk does not end at the end hash"));
        }
        Ok(Self {
            network,
            end_height,
            end_hash,
            sprout_root,
            total_joinsplits,
            chunks,
        })
    }

    /// SHA-256 of the canonical encoding.
    pub fn sha256(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }

    /// Total bytes of all chunks.
    pub fn total_bytes(&self) -> u64 {
        self.chunks.iter().map(|c| c.byte_len).sum()
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.bytes.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
    }
    fn array32(&mut self) -> Option<[u8; 32]> {
        self.take(32).map(|b| b.try_into().expect("32 bytes"))
    }
}

// ─── Chunks ────────────────────────────────────────────────────────────────

fn chunk_header(network: P2pNetwork, first_height: u32, last_height: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    out.extend_from_slice(CHUNK_MAGIC);
    out.push(PACK_FORMAT_VERSION);
    out.push(network_tag(network));
    out.extend_from_slice(&first_height.to_le_bytes());
    out.extend_from_slice(&last_height.to_le_bytes());
    out
}

/// Encode one block entry.
pub fn encode_block(hash: &[u8; 32], joinsplits: &[SproutJoinSplit]) -> ZeckResult<Vec<u8>> {
    let count = u32::try_from(joinsplits.len())
        .ok()
        .filter(|n| *n <= MAX_JOINSPLITS_PER_BLOCK)
        .ok_or_else(|| pack_error("a block has more JoinSplits than the format allows"))?;
    let mut out = Vec::with_capacity(36 + joinsplits.len() * JOINSPLIT_RECORD_LEN);
    out.extend_from_slice(hash);
    out.extend_from_slice(&count.to_le_bytes());
    for js in joinsplits {
        out.extend_from_slice(&js.txid);
        out.extend_from_slice(&js.js_index.to_le_bytes());
        out.extend_from_slice(&js.anchor);
        for nf in &js.nullifiers {
            out.extend_from_slice(nf);
        }
        for cm in &js.commitments {
            out.extend_from_slice(cm);
        }
        out.extend_from_slice(&js.ephemeral_key);
        out.extend_from_slice(&js.random_seed);
        out.extend_from_slice(&js.joinsplit_pubkey);
        for ct in &js.ciphertexts {
            if ct.len() != CIPHERTEXT_LEN {
                return Err(pack_error(format!(
                    "a JoinSplit ciphertext is {} bytes, not {CIPHERTEXT_LEN}",
                    ct.len()
                )));
            }
            out.extend_from_slice(ct);
        }
    }
    Ok(out)
}

fn decode_joinsplit(record: &[u8]) -> SproutJoinSplit {
    debug_assert_eq!(record.len(), JOINSPLIT_RECORD_LEN);
    let mut r = Cursor {
        bytes: record,
        pos: 0,
    };
    // Every read is in bounds: the record has exactly JOINSPLIT_RECORD_LEN
    // bytes, the sum of the fields read here.
    let txid = r.array32().expect("fixed-size record");
    let js_index = r.u64().expect("fixed-size record");
    let anchor = r.array32().expect("fixed-size record");
    let nullifiers = [
        r.array32().expect("fixed-size record"),
        r.array32().expect("fixed-size record"),
    ];
    let commitments = [
        r.array32().expect("fixed-size record"),
        r.array32().expect("fixed-size record"),
    ];
    let ephemeral_key = r.array32().expect("fixed-size record");
    let random_seed = r.array32().expect("fixed-size record");
    let joinsplit_pubkey = r.array32().expect("fixed-size record");
    let ciphertexts = [
        r.take(CIPHERTEXT_LEN).expect("fixed-size record").to_vec(),
        r.take(CIPHERTEXT_LEN).expect("fixed-size record").to_vec(),
    ];
    SproutJoinSplit {
        txid,
        js_index,
        anchor,
        nullifiers,
        commitments,
        ephemeral_key,
        random_seed,
        joinsplit_pubkey,
        ciphertexts,
    }
}

/// Writes one chunk to `<name>.partial`, renaming it into place only once
/// complete, so a half-written chunk is never mistaken for a finished one.
pub struct ChunkWriter {
    file: io::BufWriter<fs::File>,
    partial: PathBuf,
    path: PathBuf,
    hasher: Sha256,
    byte_len: u64,
    next_height: u32,
    first_height: u32,
    last_height: u32,
    last_hash: Option<[u8; 32]>,
    joinsplits: u64,
}

impl ChunkWriter {
    pub fn create(
        dir: &Path,
        index: usize,
        network: P2pNetwork,
        first_height: u32,
        last_height: u32,
    ) -> ZeckResult<Self> {
        let path = dir.join(chunk_file_name(index));
        let partial = dir.join(format!("{}.partial", chunk_file_name(index)));
        let file = fs::File::create(&partial).map_err(|err| io_error(&partial, err))?;
        let mut writer = Self {
            file: io::BufWriter::with_capacity(1 << 20, file),
            partial,
            path,
            hasher: Sha256::new(),
            byte_len: 0,
            next_height: first_height,
            first_height,
            last_height,
            last_hash: None,
            joinsplits: 0,
        };
        writer.write(&chunk_header(network, first_height, last_height))?;
        Ok(writer)
    }

    fn write(&mut self, bytes: &[u8]) -> ZeckResult<()> {
        self.file
            .write_all(bytes)
            .map_err(|err| io_error(&self.partial, err))?;
        self.hasher.update(bytes);
        self.byte_len += bytes.len() as u64;
        Ok(())
    }

    /// The height the next block must have.
    pub fn next_height(&self) -> u32 {
        self.next_height
    }

    /// Whether every block of the range has been written.
    pub fn is_full(&self) -> bool {
        self.next_height > self.last_height
    }

    /// Append the block at `height`. Heights must be consecutive.
    pub fn push(
        &mut self,
        height: u32,
        hash: &[u8; 32],
        joinsplits: &[SproutJoinSplit],
    ) -> ZeckResult<()> {
        if height != self.next_height || self.is_full() {
            return Err(pack_error(format!(
                "block at height {height} does not belong next in a chunk expecting {}",
                self.next_height
            )));
        }
        let bytes = encode_block(hash, joinsplits)?;
        self.write(&bytes)?;
        self.joinsplits += joinsplits.len() as u64;
        self.last_hash = Some(*hash);
        self.next_height += 1;
        Ok(())
    }

    /// Flush, sync and rename into place.
    pub fn finish(mut self) -> ZeckResult<ChunkEntry> {
        if !self.is_full() {
            return Err(pack_error(format!(
                "chunk ending at {} finished early, at height {}",
                self.last_height, self.next_height
            )));
        }
        self.file
            .flush()
            .map_err(|err| io_error(&self.partial, err))?;
        let file = self
            .file
            .into_inner()
            .map_err(|err| io_error(&self.partial, err.into_error()))?;
        file.sync_all()
            .map_err(|err| io_error(&self.partial, err))?;
        drop(file);
        fs::rename(&self.partial, &self.path).map_err(|err| io_error(&self.path, err))?;
        Ok(ChunkEntry {
            first_height: self.first_height,
            last_height: self.last_height,
            last_hash: self.last_hash.expect("a full chunk has a last block"),
            joinsplits: self.joinsplits,
            byte_len: self.byte_len,
            sha256: self.hasher.finalize().into(),
        })
    }
}

/// A `Read` that hashes and counts everything read through it.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    read: u64,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.read += n as u64;
        Ok(n)
    }
}

/// Streams one chunk's blocks in height order.
///
/// Nothing a chunk says is trusted until [`ChunkReader::finish`] returns:
/// that is where the bytes read are compared with the manifest's length and
/// SHA-256. A caller must therefore treat every block it took from the
/// reader as provisional until then — the scan does, by checkpointing only
/// at chunk boundaries.
pub struct ChunkReader {
    reader: HashingReader<BufReader<fs::File>>,
    path: PathBuf,
    entry: ChunkEntry,
    next_height: u32,
    joinsplits: u64,
    last_hash: Option<[u8; 32]>,
}

impl ChunkReader {
    pub fn open(path: &Path, network: P2pNetwork, entry: &ChunkEntry) -> ZeckResult<Self> {
        let file = fs::File::open(path).map_err(|err| io_error(path, err))?;
        let len = file.metadata().map_err(|err| io_error(path, err))?.len();
        if len != entry.byte_len {
            return Err(pack_error(format!(
                "{} is {len} bytes; the manifest says {}. It is truncated, still \
                 downloading, or from a different pack.",
                path.display(),
                entry.byte_len
            )));
        }
        let mut reader = Self {
            reader: HashingReader {
                inner: BufReader::with_capacity(1 << 20, file),
                hasher: Sha256::new(),
                read: 0,
            },
            path: path.to_owned(),
            entry: entry.clone(),
            next_height: entry.first_height,
            joinsplits: 0,
            last_hash: None,
        };
        let mut header = [0u8; 18];
        reader.read_exact(&mut header)?;
        if header[..] != chunk_header(network, entry.first_height, entry.last_height)[..] {
            return Err(pack_error(format!(
                "{} is not the chunk the manifest describes (wrong magic, version, \
                 network or height range)",
                path.display()
            )));
        }
        Ok(reader)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> ZeckResult<()> {
        self.reader.read_exact(buf).map_err(|err| {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                pack_error(format!("{} ends early", self.path.display()))
            } else {
                io_error(&self.path, err)
            }
        })
    }

    /// The next block, or `None` once the chunk's last height has been read.
    pub fn next_block(&mut self) -> ZeckResult<Option<PackBlock>> {
        if self.next_height > self.entry.last_height {
            return Ok(None);
        }
        let mut head = [0u8; 36];
        self.read_exact(&mut head)?;
        let hash: [u8; 32] = head[..32].try_into().expect("32 bytes");
        let count = u32::from_le_bytes(head[32..].try_into().expect("4 bytes"));
        if count > MAX_JOINSPLITS_PER_BLOCK {
            return Err(pack_error(format!(
                "{} claims {count} JoinSplits at height {}",
                self.path.display(),
                self.next_height
            )));
        }
        let mut joinsplits = Vec::with_capacity(count as usize);
        let mut record = vec![0u8; JOINSPLIT_RECORD_LEN];
        for _ in 0..count {
            self.read_exact(&mut record)?;
            joinsplits.push(decode_joinsplit(&record));
        }
        let height = self.next_height;
        self.next_height += 1;
        self.joinsplits += u64::from(count);
        self.last_hash = Some(hash);
        Ok(Some(PackBlock {
            height,
            hash,
            joinsplits,
        }))
    }

    /// Confirm the chunk was exactly what the manifest pinned.
    ///
    /// Must be called after the last block; until it returns `Ok`, nothing
    /// read from this chunk may be persisted.
    pub fn finish(mut self) -> ZeckResult<()> {
        if self.next_height <= self.entry.last_height {
            return Err(pack_error(format!(
                "{} was not read to its end",
                self.path.display()
            )));
        }
        let mut trailing = [0u8; 1];
        let extra = self
            .reader
            .read(&mut trailing)
            .map_err(|err| io_error(&self.path, err))?;
        let digest: [u8; 32] = self.reader.hasher.finalize().into();
        if extra != 0
            || self.reader.read != self.entry.byte_len
            || digest != self.entry.sha256
            || self.joinsplits != self.entry.joinsplits
            || self.last_hash != Some(self.entry.last_hash)
        {
            return Err(pack_error(format!(
                "{} does not match the manifest's hash. The file is corrupt or has been \
                 altered; nothing from it was kept. Download it again.",
                self.path.display()
            )));
        }
        Ok(())
    }
}

// ─── Opening a pack ────────────────────────────────────────────────────────

/// Whether the manifest is one this release vouches for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackTrust {
    /// Its manifest hash is in [`PINNED_PACKS`].
    Pinned,
    /// Not pinned. Only accepted off mainnet.
    Unpinned,
}

/// An opened, structurally valid pack whose manifest is acceptable for its
/// network. Chunk contents are verified as they are read.
#[derive(Debug, Clone)]
pub struct SproutPack {
    dir: PathBuf,
    manifest: PackManifest,
    manifest_sha256: [u8; 32],
    trust: PackTrust,
}

/// One line telling a user that a pinned pack exists for `network`, for the
/// cost warning. `None` while this release pins none.
pub fn pack_available_line(network: P2pNetwork) -> Option<String> {
    let pin = PINNED_PACKS.iter().find(|pin| pin.network == network)?;
    Some(format!(
        "A Sprout pack covering blocks 1 to {} is published with this release. Scanning \
         with it (--sprout-pack in the CLI, or the pack folder in the app) replaces most of \
         this download with a few gigabytes of files, with the same result.",
        pin.end_height
    ))
}

/// Why a scan will not use an unpinned mainnet pack.
pub(crate) fn unpinned_mainnet(pack: &SproutPack) -> ZeckError {
    pack_error(format!(
        "this mainnet pack (manifest SHA-256 {}, to height {}) is not one this version of \
         Argos vouches for. A pack decides which notes are found and which are reported \
         spent, so only a pinned pack is used. Use the pack published with this release, \
         or scan without one.",
        to_hex(&pack.manifest_sha256),
        pack.manifest.end_height
    ))
}

/// Whether `manifest_sha256` is pinned for `network` at `end_height`.
fn pinned(network: P2pNetwork, manifest_sha256: &[u8; 32], end_height: u32) -> bool {
    PINNED_PACKS.iter().any(|pin| {
        pin.network == network
            && pin.end_height == end_height
            && from_hex32(pin.manifest_sha256).as_ref() == Some(manifest_sha256)
    })
}

impl SproutPack {
    /// Open the pack in `dir` for a scan on `network`.
    ///
    /// Reads only the manifest. Refuses a pack for another network, and on
    /// mainnet any pack whose manifest hash this release has not pinned.
    pub fn open(dir: &Path, network: P2pNetwork) -> ZeckResult<Self> {
        let pack = Self::open_for_inspection(dir, network)?;
        if pack.trust == PackTrust::Unpinned && matches!(network, P2pNetwork::Mainnet) {
            return Err(unpinned_mainnet(&pack));
        }
        Ok(pack)
    }

    /// [`open`](Self::open) without the pinning policy, for a maintainer
    /// checking a pack before its hash is pinned. A scan refuses an unpinned
    /// mainnet pack however it was opened.
    pub fn open_for_inspection(dir: &Path, network: P2pNetwork) -> ZeckResult<Self> {
        let path = dir.join(MANIFEST_FILE);
        let file = fs::File::open(&path).map_err(|err| {
            pack_error(format!(
                "no pack manifest at {} ({err}). Point at the folder holding \
                 {MANIFEST_FILE} and the chunk files.",
                path.display()
            ))
        })?;
        let mut bytes = Vec::new();
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|err| io_error(&path, err))?;
        if bytes.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(pack_error(format!("{} is too large", path.display())));
        }
        let manifest_sha256: [u8; 32] = Sha256::digest(&bytes).into();
        let manifest = PackManifest::from_bytes(&bytes)?;
        if manifest.network != network {
            return Err(pack_error(format!(
                "this pack is for {}, but the scan is on {}",
                network_name(manifest.network),
                network_name(network)
            )));
        }
        let trust = if pinned(network, &manifest_sha256, manifest.end_height) {
            PackTrust::Pinned
        } else {
            PackTrust::Unpinned
        };
        Ok(Self {
            dir: dir.to_owned(),
            manifest,
            manifest_sha256,
            trust,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn manifest(&self) -> &PackManifest {
        &self.manifest
    }
    pub fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
    pub fn trust(&self) -> PackTrust {
        self.trust
    }
    pub fn end_height(&self) -> u32 {
        self.manifest.end_height
    }

    /// Open chunk `index` for reading.
    pub fn open_chunk(&self, index: usize) -> ZeckResult<ChunkReader> {
        let entry = self
            .manifest
            .chunks
            .get(index)
            .ok_or_else(|| pack_error(format!("no chunk {index}")))?;
        ChunkReader::open(
            &self.dir.join(chunk_file_name(index)),
            self.manifest.network,
            entry,
        )
    }

    /// Check every chunk end to end and recompute the Sprout tree root.
    ///
    /// The scan does the same checks as it goes; this is for a maintainer
    /// verifying a pack before pinning it, or a user checking a download.
    pub fn verify_all(&self, mut progress: impl FnMut(u32)) -> ZeckResult<()> {
        let summary = summarize_chunks(&self.dir, self.manifest.network, self.end_height(), |h| {
            progress(h)
        })?;
        if summary.chunks != self.manifest.chunks
            || summary.sprout_root != self.manifest.sprout_root
            || summary.total_joinsplits != self.manifest.total_joinsplits
        {
            return Err(pack_error(
                "the chunks do not reproduce the manifest's totals or Sprout tree root",
            ));
        }
        Ok(())
    }
}

/// What reading a directory's chunks from scratch yields.
pub struct ChunkSummary {
    pub chunks: Vec<ChunkEntry>,
    pub sprout_root: [u8; 32],
    pub total_joinsplits: u64,
}

/// Read every chunk of a pack ending at `end_height`, recomputing each
/// chunk's entry and the Sprout commitment tree root at the end.
///
/// Used both to verify a pack and to write the manifest at the end of a
/// build, so the manifest a builder writes is derived from the files on
/// disk, not from what it believes it wrote.
pub fn summarize_chunks(
    dir: &Path,
    network: P2pNetwork,
    end_height: u32,
    mut progress: impl FnMut(u32),
) -> ZeckResult<ChunkSummary> {
    let mut tree = crate::sprout_witness::IncrementalMerkleTree::default();
    let mut chunks = Vec::new();
    let mut total = 0u64;
    for index in 0..chunk_count(end_height) {
        let entry = scan_chunk_file(dir, index, network, end_height, |block| {
            for js in &block.joinsplits {
                for cm in &js.commitments {
                    tree.append(*cm)
                        .map_err(|err| pack_error(format!("height {}: {err}", block.height)))?;
                }
            }
            progress(block.height);
            Ok(())
        })?;
        total += entry.joinsplits;
        chunks.push(entry);
    }
    Ok(ChunkSummary {
        chunks,
        sprout_root: tree.root(),
        total_joinsplits: total,
    })
}

/// Read one chunk file with no manifest to check it against, returning the
/// entry it would have. Structural checks only (header, heights, lengths).
pub fn scan_chunk_file(
    dir: &Path,
    index: usize,
    network: P2pNetwork,
    end_height: u32,
    mut each: impl FnMut(&PackBlock) -> ZeckResult<()>,
) -> ZeckResult<ChunkEntry> {
    let (first_height, last_height) = chunk_range(index, end_height)
        .ok_or_else(|| pack_error(format!("no chunk {index} below height {end_height}")))?;
    let path = dir.join(chunk_file_name(index));
    let file = fs::File::open(&path).map_err(|err| io_error(&path, err))?;
    let byte_len = file.metadata().map_err(|err| io_error(&path, err))?.len();
    // Read it as the manifest would describe it, minus the hash and counts
    // we are about to compute.
    let provisional = ChunkEntry {
        first_height,
        last_height,
        last_hash: [0; 32],
        joinsplits: 0,
        byte_len,
        sha256: [0; 32],
    };
    drop(file);
    let mut reader = ChunkReader::open(&path, network, &provisional)?;
    while let Some(block) = reader.next_block()? {
        each(&block)?;
    }
    let mut trailing = [0u8; 1];
    if reader
        .reader
        .read(&mut trailing)
        .map_err(|err| io_error(&path, err))?
        != 0
    {
        return Err(pack_error(format!("{} has trailing bytes", path.display())));
    }
    Ok(ChunkEntry {
        first_height,
        last_height,
        last_hash: reader.last_hash.expect("a chunk holds at least one block"),
        joinsplits: reader.joinsplits,
        byte_len: reader.reader.read,
        sha256: reader.reader.hasher.finalize().into(),
    })
}

/// Write `manifest` into `dir` atomically.
pub fn write_manifest(dir: &Path, manifest: &PackManifest) -> ZeckResult<[u8; 32]> {
    let bytes = manifest.to_bytes();
    let path = dir.join(MANIFEST_FILE);
    let partial = dir.join(format!("{MANIFEST_FILE}.partial"));
    {
        let mut file = fs::File::create(&partial).map_err(|err| io_error(&partial, err))?;
        file.write_all(&bytes)
            .map_err(|err| io_error(&partial, err))?;
        file.sync_all().map_err(|err| io_error(&partial, err))?;
    }
    fs::rename(&partial, &path).map_err(|err| io_error(&path, err))?;
    Ok(Sha256::digest(&bytes).into())
}

/// A ready-to-paste [`PINNED_PACKS`] entry.
pub fn pinned_entry_source(manifest: &PackManifest, manifest_sha256: &[u8; 32]) -> String {
    let network = match manifest.network {
        P2pNetwork::Mainnet => "Mainnet",
        P2pNetwork::Testnet => "Testnet",
        P2pNetwork::Regtest => "Regtest",
    };
    format!(
        "PinnedPack {{\n    network: P2pNetwork::{network},\n    manifest_sha256: \"{}\",\n    \
         end_height: {},\n}},",
        to_hex(manifest_sha256),
        manifest.end_height
    )
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A deterministic JoinSplit whose bytes all derive from `tag`.
    pub(crate) fn joinsplit(tag: u8) -> SproutJoinSplit {
        let b = |offset: u8| [tag.wrapping_add(offset); 32];
        SproutJoinSplit {
            txid: b(1),
            js_index: u64::from(tag),
            anchor: b(2),
            nullifiers: [b(3), b(4)],
            commitments: [b(5), b(6)],
            ephemeral_key: b(7),
            random_seed: b(8),
            joinsplit_pubkey: b(9),
            ciphertexts: [vec![tag; CIPHERTEXT_LEN], vec![tag ^ 0xff; CIPHERTEXT_LEN]],
        }
    }

    /// The hash a synthetic chain gives the block at `height`.
    pub(crate) fn block_hash(height: u32) -> [u8; 32] {
        let mut hash = [0xA5; 32];
        hash[..4].copy_from_slice(&height.to_le_bytes());
        hash
    }

    /// JoinSplits a synthetic chain puts in the block at `height`.
    pub(crate) fn block_joinsplits(height: u32) -> Vec<SproutJoinSplit> {
        // Sparse past 1,000 so multi-chunk test packs stay a few megabytes.
        if height > 1_000 {
            return Vec::new();
        }
        match height % 7 {
            0 => vec![
                joinsplit(height as u8),
                joinsplit(height.wrapping_add(1) as u8),
            ],
            3 => vec![joinsplit(height as u8)],
            _ => Vec::new(),
        }
    }

    /// Write a complete synthetic pack ending at `end_height`.
    pub(crate) fn write_pack(dir: &Path, network: P2pNetwork, end_height: u32) -> PackManifest {
        for index in 0..chunk_count(end_height) {
            let (first, last) = chunk_range(index, end_height).unwrap();
            let mut writer = ChunkWriter::create(dir, index, network, first, last).unwrap();
            for height in first..=last {
                writer
                    .push(height, &block_hash(height), &block_joinsplits(height))
                    .unwrap();
            }
            writer.finish().unwrap();
        }
        let summary = summarize_chunks(dir, network, end_height, |_| {}).unwrap();
        let manifest = PackManifest {
            network,
            end_height,
            end_hash: block_hash(end_height),
            sprout_root: summary.sprout_root,
            total_joinsplits: summary.total_joinsplits,
            chunks: summary.chunks,
        };
        write_manifest(dir, &manifest).unwrap();
        manifest
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn a_joinsplit_record_round_trips() {
        let js = joinsplit(42);
        let bytes = encode_block(&[7; 32], std::slice::from_ref(&js)).unwrap();
        assert_eq!(bytes.len(), 36 + JOINSPLIT_RECORD_LEN);
        let back = decode_joinsplit(&bytes[36..]);
        assert_eq!(
            encode_block(&[7; 32], &[back]).unwrap(),
            bytes,
            "every field survives the round trip"
        );
    }

    #[test]
    fn chunk_boundaries_are_fixed() {
        assert_eq!(chunk_range(0, 250_000), Some((1, 100_000)));
        assert_eq!(chunk_range(1, 250_000), Some((100_001, 200_000)));
        assert_eq!(chunk_range(2, 250_000), Some((200_001, 250_000)));
        assert_eq!(chunk_range(3, 250_000), None);
        assert_eq!(chunk_count(250_000), 3);
        assert_eq!(chunk_count(200_000), 2);
        assert_eq!(chunk_range(1, 200_000), Some((100_001, 200_000)));
    }

    #[test]
    fn a_written_pack_reads_back_block_for_block() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_pack(dir.path(), P2pNetwork::Regtest, 150);
        let pack = SproutPack::open(dir.path(), P2pNetwork::Regtest).unwrap();
        assert_eq!(pack.manifest(), &manifest);
        assert_eq!(pack.trust(), PackTrust::Unpinned);
        let mut reader = pack.open_chunk(0).unwrap();
        let mut height = 1;
        while let Some(block) = reader.next_block().unwrap() {
            assert_eq!(block.height, height);
            assert_eq!(block.hash, block_hash(height));
            assert_eq!(
                encode_block(&block.hash, &block.joinsplits).unwrap(),
                encode_block(&block.hash, &block_joinsplits(height)).unwrap()
            );
            height += 1;
        }
        assert_eq!(height, 151);
        reader.finish().unwrap();
        pack.verify_all(|_| {}).unwrap();
    }

    /// Two builds of the same chain must hash identically, or nobody can
    /// reproduce a pinned pack.
    #[test]
    fn the_same_chain_always_gives_the_same_manifest_hash() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let ma = write_pack(a.path(), P2pNetwork::Testnet, 120);
        let mb = write_pack(b.path(), P2pNetwork::Testnet, 120);
        assert_eq!(ma.sha256(), mb.sha256());
        assert_eq!(
            fs::read(a.path().join(MANIFEST_FILE)).unwrap(),
            fs::read(b.path().join(MANIFEST_FILE)).unwrap()
        );
    }

    #[test]
    fn a_flipped_byte_in_a_chunk_is_caught_at_finish() {
        let dir = tempfile::tempdir().unwrap();
        write_pack(dir.path(), P2pNetwork::Regtest, 50);
        let path = dir.path().join(chunk_file_name(0));
        let mut bytes = fs::read(&path).unwrap();
        // Height 50 has no JoinSplits (36 bytes); just before it is the end of
        // height 49's second ciphertext. Structurally fine, so only the hash
        // can catch it.
        let inside = bytes.len() - 36 - 100;
        bytes[inside] ^= 1;
        fs::write(&path, bytes).unwrap();
        let pack = SproutPack::open(dir.path(), P2pNetwork::Regtest).unwrap();
        let mut reader = pack.open_chunk(0).unwrap();
        while reader.next_block().unwrap().is_some() {}
        let err = reader.finish().unwrap_err().to_string();
        assert!(err.contains("does not match the manifest"), "{err}");
        assert!(pack.verify_all(|_| {}).is_err());
    }

    #[test]
    fn a_truncated_chunk_is_refused_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        write_pack(dir.path(), P2pNetwork::Regtest, 50);
        let path = dir.path().join(chunk_file_name(0));
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        let pack = SproutPack::open(dir.path(), P2pNetwork::Regtest).unwrap();
        let err = pack.open_chunk(0).err().unwrap().to_string();
        assert!(err.contains("truncated"), "{err}");
    }

    #[test]
    fn an_unpinned_mainnet_pack_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write_pack(dir.path(), P2pNetwork::Mainnet, 20);
        let err = SproutPack::open(dir.path(), P2pNetwork::Mainnet)
            .err()
            .unwrap()
            .to_string();
        assert!(
            err.contains("not one this version of Argos vouches for"),
            "{err}"
        );
        // A maintainer can still inspect and verify it before pinning.
        let pack = SproutPack::open_for_inspection(dir.path(), P2pNetwork::Mainnet).unwrap();
        assert_eq!(pack.trust(), PackTrust::Unpinned);
        pack.verify_all(|_| {}).unwrap();
    }

    #[test]
    fn a_pack_for_another_network_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        write_pack(dir.path(), P2pNetwork::Testnet, 20);
        let err = SproutPack::open(dir.path(), P2pNetwork::Regtest)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("for testnet"), "{err}");
    }

    #[test]
    fn a_manifest_off_its_fixed_boundaries_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut manifest = write_pack(dir.path(), P2pNetwork::Regtest, 20);
        manifest.chunks[0].first_height = 2;
        assert!(PackManifest::from_bytes(&manifest.to_bytes()).is_err());
        let mut bytes = write_pack(dir.path(), P2pNetwork::Regtest, 20).to_bytes();
        bytes.push(0);
        assert!(PackManifest::from_bytes(&bytes).is_err());
    }

    #[test]
    fn pinned_entries_parse() {
        for pin in PINNED_PACKS {
            assert!(from_hex32(pin.manifest_sha256).is_some());
            assert!(pin.end_height > 0);
        }
        let hex = to_hex(&[0xab; 32]);
        assert_eq!(from_hex32(&hex), Some([0xab; 32]));
    }

    #[test]
    fn mainnet_pins_the_reproduced_3_500_000_pack() {
        let mainnet: Vec<_> = PINNED_PACKS
            .iter()
            .filter(|pin| pin.network == P2pNetwork::Mainnet)
            .collect();
        assert_eq!(mainnet.len(), 1);
        assert_eq!(
            mainnet[0].manifest_sha256,
            "805435e69ae7a28c2045abcb5fa7b049de7e4c288f1f7c3d8d9529eb143ba57d"
        );
        assert_eq!(mainnet[0].end_height, 3_500_000);
    }

    #[test]
    fn a_partial_chunk_is_not_left_under_its_final_name() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = ChunkWriter::create(dir.path(), 0, P2pNetwork::Regtest, 1, 10).unwrap();
        writer.push(1, &block_hash(1), &[]).unwrap();
        assert!(!dir.path().join(chunk_file_name(0)).exists());
        assert!(writer.finish().is_err());
        assert!(!dir.path().join(chunk_file_name(0)).exists());
    }
}
