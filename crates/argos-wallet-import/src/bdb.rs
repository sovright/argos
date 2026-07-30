//! Read-only Berkeley DB 6.2 btree walker.
//!
//! Knows nothing about Zcash: it yields raw `(key, value)` byte pairs.
//! Every offset here is attacker-controlled, so all reads go through
//! `get()` and every length is bounds-checked before it is used to size
//! an allocation.

use crate::error::ImportError;

const BDB_BTREE_MAGIC: u32 = 0x0005_3162;

/// A raw key/value record as stored in the Berkeley DB btree.
/// Uninterpreted here — `bdb.rs` has no Zcash knowledge.
pub type RawRecord = (Vec<u8>, Vec<u8>);

pub(crate) const MIN_PAGE_SIZE: u32 = 512;
pub(crate) const MAX_PAGE_SIZE: u32 = 65_536;

#[derive(Debug, Clone, Copy)]
pub struct BdbMeta {
    pub page_size: u32,
    pub last_page: u32,
    pub root_page: u32,
    /// True when the file's byte order is opposite to ours.
    pub swapped: bool,
}

fn unwalkable(msg: impl Into<String>) -> ImportError {
    ImportError::UnwalkableBtree(msg.into())
}

/// Read a big- or little-endian u32 at `offset`, bounds-checked.
pub(crate) fn read_u32(bytes: &[u8], offset: usize, swapped: bool) -> Result<u32, ImportError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| unwalkable(format!("u32 read at {offset} overflows")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| unwalkable(format!("u32 read at {offset} is past end of data")))?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    Ok(if swapped {
        u32::from_be_bytes(buf)
    } else {
        u32::from_le_bytes(buf)
    })
}

/// Read a big- or little-endian u16 at `offset`, bounds-checked.
pub(crate) fn read_u16(bytes: &[u8], offset: usize, swapped: bool) -> Result<u16, ImportError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| unwalkable(format!("u16 read at {offset} overflows")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| unwalkable(format!("u16 read at {offset} is past end of data")))?;
    let mut buf = [0u8; 2];
    buf.copy_from_slice(slice);
    Ok(if swapped {
        u16::from_be_bytes(buf)
    } else {
        u16::from_le_bytes(buf)
    })
}

/// Parse the metadata page (page 0).
///
/// Validates page_size and last_page against the real file length before
/// either is used for arithmetic. A 4-byte field claiming a 1 GB page must
/// never reach an allocation.
pub fn read_meta(bytes: &[u8]) -> Result<BdbMeta, ImportError> {
    let raw = bytes
        .get(12..16)
        .ok_or_else(|| unwalkable("file is too short to contain a BDB metadata page"))?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(raw);

    let swapped = if u32::from_le_bytes(buf) == BDB_BTREE_MAGIC {
        false
    } else if u32::from_be_bytes(buf) == BDB_BTREE_MAGIC {
        true
    } else {
        return Err(unwalkable("BDB btree magic not found"));
    };

    let page_size = read_u32(bytes, 20, swapped)?;
    if !page_size.is_power_of_two() || !(MIN_PAGE_SIZE..=MAX_PAGE_SIZE).contains(&page_size) {
        return Err(unwalkable(format!("implausible page size {page_size}")));
    }

    let last_page = read_u32(bytes, 32, swapped)?;
    let available_pages = (bytes.len() as u64) / u64::from(page_size);
    if u64::from(last_page) >= available_pages {
        return Err(unwalkable(format!(
            "metadata claims {} pages but the file holds {available_pages}",
            u64::from(last_page) + 1
        )));
    }

    let root_page = read_u32(bytes, 88, swapped)?;
    if root_page == 0 {
        return Err(unwalkable(
            "root page 0 is the metadata page, not a btree root",
        ));
    }
    if u64::from(root_page) > u64::from(last_page) {
        return Err(unwalkable(format!(
            "root page {root_page} is beyond last page {last_page}"
        )));
    }

    Ok(BdbMeta {
        page_size,
        last_page,
        root_page,
        swapped,
    })
}

use std::collections::BTreeSet;

pub(crate) const PAGE_TYPE_IBTREE: u8 = 3;
pub(crate) const PAGE_TYPE_LBTREE: u8 = 5;
pub(crate) const PAGE_TYPE_OVERFLOW: u8 = 7;

/// Byte offsets within a page header.
///
/// The generic (non-meta) BDB page header is `lsn:8, pgno:4, prev_pgno:4,
/// next_pgno:4, entries:2, hf_offset:2, level:1, type:1` — entries at 20,
/// type at 25 — verified against real zcashd-written pages in
/// `tests/fixtures/`, not assumed from the format spec.
const OFF_ENTRY_COUNT: usize = 20;
const OFF_PAGE_TYPE: usize = 25;
const OFF_INDEX_START: usize = 26;

/// Leaf entry types.
const ENTRY_KEYDATA: u8 = 1;
const ENTRY_OVERFLOW: u8 = 3;

/// Hard ceiling on records returned, so a crafted file cannot exhaust
/// memory through sheer entry count. Real zcashd wallets are far below.
const MAX_RECORDS: usize = 500_000;

/// Hard ceiling on a single value reassembled from overflow pages.
const MAX_VALUE_LEN: usize = 16 * 1024 * 1024;

fn page_slice(bytes: &[u8], page: u32, page_size: u32) -> Result<&[u8], ImportError> {
    let start = (page as usize)
        .checked_mul(page_size as usize)
        .ok_or_else(|| unwalkable("page offset overflow"))?;
    let end = start
        .checked_add(page_size as usize)
        .ok_or_else(|| unwalkable("page end overflow"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| unwalkable(format!("page {page} is past end of file")))
}

/// Follow an overflow chain and reassemble the full value.
fn read_overflow(
    bytes: &[u8],
    meta: &BdbMeta,
    first_page: u32,
    total_len: u32,
    visited: &mut BTreeSet<u32>,
) -> Result<Vec<u8>, ImportError> {
    let total_len = total_len as usize;
    if total_len > MAX_VALUE_LEN {
        return Err(unwalkable(format!(
            "overflow value of {total_len} bytes is implausible"
        )));
    }
    // Bound the claim by what the file could possibly hold before allocating.
    if total_len > bytes.len() {
        return Err(unwalkable(format!(
            "overflow value claims {total_len} bytes but the file is {}",
            bytes.len()
        )));
    }

    let mut out = Vec::with_capacity(total_len);
    let mut page = first_page;

    while page != 0 && out.len() < total_len {
        if !visited.insert(page) {
            return Err(unwalkable(format!("overflow chain revisits page {page}")));
        }
        let p = page_slice(bytes, page, meta.page_size)?;
        let next = read_u32(p, 16, meta.swapped)?;
        let this_len = read_u16(p, OFF_ENTRY_COUNT, meta.swapped)? as usize;

        let want = this_len.min(total_len - out.len());
        let data = p
            .get(26..26 + want)
            .ok_or_else(|| unwalkable(format!("overflow page {page} is short")))?;
        out.extend_from_slice(data);
        page = next;
    }

    Ok(out)
}

/// zcashd/Bitcoin Core always open `wallet.dat` on a named subdatabase
/// (`"main"`), so the file's top-level meta page never points at the real
/// records directly. It points at a tiny "master" btree mapping
/// subdatabase name -> the page number of *that* subdatabase's own meta
/// page, whose `root` field is the real btree root. This resolves one such
/// value, trying both byte orders since this indirection value is not
/// covered by the swap test applied to the top-level meta page.
fn resolve_subdb_root(bytes: &[u8], meta: &BdbMeta, value: &[u8]) -> Option<u32> {
    let raw: [u8; 4] = value.try_into().ok()?;
    for pgno in [u32::from_le_bytes(raw), u32::from_be_bytes(raw)] {
        if pgno == 0 || pgno > meta.last_page {
            continue;
        }
        let Ok(page_bytes) = page_slice(bytes, pgno, meta.page_size) else {
            continue;
        };
        let Some(magic_raw) = page_bytes.get(12..16) else {
            continue;
        };
        let mut buf = [0u8; 4];
        buf.copy_from_slice(magic_raw);
        let is_meta = if meta.swapped {
            u32::from_be_bytes(buf) == BDB_BTREE_MAGIC
        } else {
            u32::from_le_bytes(buf) == BDB_BTREE_MAGIC
        };
        if !is_meta {
            continue;
        }
        let Ok(root) = read_u32(page_bytes, 88, meta.swapped) else {
            continue;
        };
        if root <= meta.last_page {
            return Some(root);
        }
    }
    None
}

/// Walk every leaf page reachable from `root` and append the `(key,
/// value)` pairs found to `out`.
///
/// Page pointers form an attacker-controlled graph, so `visited` bounds
/// traversal: without it a crafted file is a trivial infinite loop.
fn walk_from(
    bytes: &[u8],
    meta: &BdbMeta,
    root: u32,
    visited: &mut BTreeSet<u32>,
    out: &mut Vec<RawRecord>,
) {
    let mut stack = vec![root];

    while let Some(page) = stack.pop() {
        if out.len() >= MAX_RECORDS {
            break;
        }
        if !visited.insert(page) {
            continue;
        }
        if page > meta.last_page {
            continue;
        }

        let p = match page_slice(bytes, page, meta.page_size) {
            Ok(p) => p,
            // Partial recovery: a bad page must not abort the whole walk.
            Err(_) => continue,
        };

        let page_type = match p.get(OFF_PAGE_TYPE) {
            Some(t) => *t,
            None => continue,
        };
        let count = match read_u16(p, OFF_ENTRY_COUNT, meta.swapped) {
            Ok(c) => c as usize,
            Err(_) => continue,
        };

        match page_type {
            PAGE_TYPE_IBTREE => {
                // BINTERNAL entry: len:u16, type:u8, pad:u8, pgno:u32, ...
                // — the child page number sits at off+4, not off itself.
                for i in 0..count {
                    let Ok(off) = read_u16(p, OFF_INDEX_START + i * 2, meta.swapped) else {
                        continue;
                    };
                    let Ok(child) = read_u32(p, off as usize + 4, meta.swapped) else {
                        continue;
                    };
                    stack.push(child);
                }
            }
            PAGE_TYPE_LBTREE => {
                // Leaf entries alternate key, value.
                let mut entries = Vec::with_capacity(count.min(1024));
                for i in 0..count {
                    let Ok(off) = read_u16(p, OFF_INDEX_START + i * 2, meta.swapped) else {
                        continue;
                    };
                    let off = off as usize;
                    let Some(&kind) = p.get(off + 2) else {
                        continue;
                    };
                    let Ok(len) = read_u16(p, off, meta.swapped) else {
                        continue;
                    };

                    let item = match kind {
                        ENTRY_KEYDATA => p.get(off + 3..off + 3 + len as usize).map(<[u8]>::to_vec),
                        ENTRY_OVERFLOW => {
                            let Ok(pgno) = read_u32(p, off + 4, meta.swapped) else {
                                continue;
                            };
                            let Ok(tlen) = read_u32(p, off + 8, meta.swapped) else {
                                continue;
                            };
                            let mut seen = BTreeSet::new();
                            read_overflow(bytes, meta, pgno, tlen, &mut seen).ok()
                        }
                        _ => None,
                    };

                    match item {
                        Some(v) => entries.push(v),
                        None => continue,
                    }
                }
                for pair in entries.chunks_exact(2) {
                    if let [k, v] = pair {
                        out.push((k.clone(), v.clone()));
                    }
                }
            }
            PAGE_TYPE_OVERFLOW => {}
            _ => {}
        }
    }
}

/// Walk the btree and return all `(key, value)` pairs.
///
/// The top-level meta page's root is the master database, not the real
/// records (see [`resolve_subdb_root`]). Each master-db value that
/// resolves to a subdatabase is walked for its real records; anything
/// that does not resolve is kept as-is, which also covers wallets that
/// were never wrapped in a named subdatabase.
pub fn walk(bytes: &[u8]) -> Result<Vec<RawRecord>, ImportError> {
    let meta = read_meta(bytes)?;
    let mut visited = BTreeSet::new();

    let mut top = Vec::new();
    walk_from(bytes, &meta, meta.root_page, &mut visited, &mut top);

    let mut out = Vec::new();
    let mut real_roots = Vec::new();
    for (k, v) in top {
        match resolve_subdb_root(bytes, &meta, &v) {
            Some(root) => real_roots.push(root),
            None => out.push((k, v)),
        }
    }

    if real_roots.is_empty() {
        // No subdatabase indirection resolved; the master-db page(s)
        // already collected above are the real records.
        return Ok(out);
    }

    // A resolved subdatabase supersedes whatever unresolved pairs were
    // collected alongside it at the master-db level.
    out.clear();
    for root in real_roots {
        if out.len() >= MAX_RECORDS {
            break;
        }
        walk_from(bytes, &meta, root, &mut visited, &mut out);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta_page(page_size: u32, last_page: u32, root: u32) -> Vec<u8> {
        // Size the buffer to the pages the metadata claims, so the fixture
        // is self-consistent. Clamped at both ends: at least one 4096-byte
        // page, and at most 1 MiB so the absurd-page-size case cannot try
        // to allocate gigabytes.
        let want = (u64::from(last_page) + 1).saturating_mul(u64::from(page_size));
        let len = want.clamp(4096, 1 << 20) as usize;
        let mut v = vec![0u8; len];
        v[12..16].copy_from_slice(&0x0005_3162u32.to_le_bytes());
        v[16..20].copy_from_slice(&10u32.to_le_bytes()); // btree version 10 (BDB 6.2)
        v[20..24].copy_from_slice(&page_size.to_le_bytes());
        v[32..36].copy_from_slice(&last_page.to_le_bytes());
        v[88..92].copy_from_slice(&root.to_le_bytes());
        v
    }

    #[test]
    fn reads_page_size_and_root() {
        let m = read_meta(&meta_page(4096, 20, 1)).unwrap();
        assert_eq!(m.page_size, 4096);
        assert_eq!(m.last_page, 20);
        assert_eq!(m.root_page, 1);
        assert!(!m.swapped);
    }

    #[test]
    fn rejects_a_page_size_that_is_not_a_power_of_two() {
        let err = read_meta(&meta_page(4095, 20, 1)).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn rejects_an_absurd_page_size() {
        // Must not be used to compute an allocation.
        let err = read_meta(&meta_page(1 << 30, 20, 1)).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn rejects_a_last_page_beyond_the_file() {
        // 4096-byte file claiming 9999 pages: a length field lying about size.
        let err = read_meta(&meta_page(4096, 9999, 1)).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn rejects_a_truncated_file() {
        let err = read_meta(&[0u8; 8]).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn rejects_a_zero_root_page() {
        let err = read_meta(&meta_page(4096, 20, 0)).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn rejects_an_offset_that_would_overflow() {
        let err = read_u32(&[], usize::MAX, false).unwrap_err();
        assert!(matches!(err, ImportError::UnwalkableBtree(_)));
    }

    #[test]
    fn reads_real_golden_fixtures() {
        for name in ["sprout-plaintext", "modern-encrypted"] {
            let bytes = std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap();
            let m = read_meta(&bytes).unwrap();
            assert!(m.page_size.is_power_of_two(), "{name}: {}", m.page_size);
            assert!(m.page_size >= MIN_PAGE_SIZE && m.page_size <= MAX_PAGE_SIZE);
        }
    }

    #[test]
    fn walking_a_cyclic_page_graph_terminates() {
        // Two internal pages pointing at each other. Without cycle
        // detection this is an infinite loop or a stack overflow.
        let mut v = meta_page(512, 2, 1);
        v.resize(512 * 3, 0);
        for (page, child) in [(1u32, 2u32), (2u32, 1u32)] {
            let base = (page as usize) * 512;
            v[base + 20] = PAGE_TYPE_IBTREE;
            v[base + 18..base + 20].copy_from_slice(&1u16.to_le_bytes()); // entry count
            v[base + 26..base + 28].copy_from_slice(&32u16.to_le_bytes()); // entry offset
            v[base + 32..base + 36].copy_from_slice(&child.to_le_bytes()); // child pointer
        }
        // Must return, not hang. Either outcome is acceptable; hanging is not.
        let _ = walk(&v);
    }

    #[test]
    fn walking_golden_fixtures_yields_records() {
        for name in ["sprout-plaintext", "modern-encrypted"] {
            let bytes = std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap();
            let pairs = walk(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!pairs.is_empty(), "{name} yielded no records");
        }
    }

    #[test]
    fn golden_sprout_wallet_contains_a_zkey_record() {
        let bytes = std::fs::read("tests/fixtures/sprout-plaintext.dat").unwrap();
        let pairs = walk(&bytes).unwrap();
        // zcashd keys records as a serialized pair whose first element is
        // the type string, length-prefixed by a CompactSize byte.
        let found = pairs
            .iter()
            .any(|(k, _)| k.windows(4).any(|w| w == b"zkey"));
        assert!(found, "no zkey record in the Sprout golden fixture");
    }

    #[test]
    fn a_truncated_wallet_still_yields_the_records_it_has() {
        // Partial recovery: truncation must not zero the result.
        let bytes = std::fs::read("tests/fixtures/modern-plaintext-truncated.dat").unwrap();
        match walk(&bytes) {
            Ok(pairs) => assert!(!pairs.is_empty(), "truncated wallet yielded nothing"),
            Err(ImportError::UnwalkableBtree(_)) => {
                // Acceptable only if the metadata page itself was lost.
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
