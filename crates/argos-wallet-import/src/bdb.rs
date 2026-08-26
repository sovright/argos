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

/// On a `P_OVERFLOW` page the two 16-bit header fields are *overloaded*:
/// the count of payload bytes carried by that page lives in `hf_offset`
/// (offset 22), and `entries` (offset 20) holds a vestigial reference
/// count that Berkeley DB's writer hardcodes to 1.
///
/// Berkeley DB 6.2.32, `src/dbinc/db_page.h`:
///
/// ```text
/// *  Overflow page overloads:
/// *      The amount of overflow data stored on each page is stored in the
/// *      hf_offset field.
/// *
/// *      Before 4.3 the implementation reference counted overflow items ...
/// *      The reference count is stored in the entries field.
/// #define OV_LEN(p)  (((PAGE *)p)->hf_offset)
/// #define OV_REF(p)  (((PAGE *)p)->entries)
/// ```
///
/// and `src/db/db_overflow.c` `__db_poff` writes exactly that pairing:
/// `OV_LEN(pagep) = pagespace; OV_REF(pagep) = 1;`. Reading offset 20
/// therefore yields a constant 1, not a length.
const OFF_OVERFLOW_LEN: usize = 22;

/// `SIZEOF_PAGE` in `db_page.h`: the generic page header is 26 bytes, so
/// both a btree page's index table and an overflow page's payload begin
/// here. (BDB inserts a checksum/IV block at this point when the database
/// was created with `DB_AM_CHKSUM`/`DB_AM_ENCRYPT`; zcashd creates neither,
/// which the golden fixtures confirm.)
const SIZEOF_PAGE: usize = 26;

/// Leaf entry types.
const ENTRY_KEYDATA: u8 = 1;
const ENTRY_OVERFLOW: u8 = 3;

/// Hard ceiling on records returned, so a crafted file cannot exhaust
/// memory through sheer entry count. Real zcashd wallets are far below.
const MAX_RECORDS: usize = 500_000;

/// Hard ceiling on a single value reassembled from overflow pages.
const MAX_VALUE_LEN: usize = 16 * 1024 * 1024;

/// Hard ceiling on total pages visited across an entire `walk` call — the
/// master-level walk plus every subdatabase walk it spawns. Each
/// `walk_from` invocation gets its own `visited` set (see [`walk`]), so
/// this budget is what keeps total work bounded across all of them.
const MAX_PAGES_VISITED: usize = 2_000_000;

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
    // Page 0 is always the BDB metadata page, never a valid overflow page.
    // A zeroed or corrupted first-page pointer must be rejected, not read
    // as a completed zero-length chain when the caller actually wants
    // `total_len` bytes.
    if first_page == 0 && total_len > 0 {
        return Err(unwalkable(
            "overflow chain claims a nonzero length but starts at page 0",
        ));
    }

    let mut out = Vec::with_capacity(total_len);
    let mut page = first_page;

    while page != 0 && out.len() < total_len {
        if !visited.insert(page) {
            return Err(unwalkable(format!("overflow chain revisits page {page}")));
        }
        let p = page_slice(bytes, page, meta.page_size)?;
        let next = read_u32(p, 16, meta.swapped)?;
        let this_len = read_u16(p, OFF_OVERFLOW_LEN, meta.swapped)? as usize;

        let want = this_len.min(total_len - out.len());
        let data = p
            .get(SIZEOF_PAGE..SIZEOF_PAGE + want)
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
/// traversal within this call: without it a crafted file is a trivial
/// infinite loop. `visited` is private to each `walk_from` invocation (see
/// [`walk`]) so that one sub-tree's traversal can never cause another's to
/// be silently skipped; `budget` is shared across every invocation in a
/// single `walk` call and bounds total work across all of them.
fn walk_from(
    bytes: &[u8],
    meta: &BdbMeta,
    root: u32,
    visited: &mut BTreeSet<u32>,
    budget: &mut usize,
    out: &mut Vec<RawRecord>,
) {
    let mut stack = vec![root];

    while let Some(page) = stack.pop() {
        if out.len() >= MAX_RECORDS {
            break;
        }
        if *budget == 0 {
            break;
        }
        if !visited.insert(page) {
            continue;
        }
        if page > meta.last_page {
            continue;
        }
        *budget -= 1;

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
                // Leaf entries alternate key, value. Each slot's read result
                // is kept at its own index — `None` for a failed read — so a
                // single corrupted entry cannot shift the key/value pairing
                // of any entry after it. Compacting successful reads into a
                // dense vector before pairing (e.g. `chunks_exact` over only
                // the `Some`s) would desynchronize every later entry on the
                // page; see the leaf-desync regression test below.
                let mut entries: Vec<Option<Vec<u8>>> = Vec::with_capacity(count.min(1024));
                for i in 0..count {
                    let Ok(off) = read_u16(p, OFF_INDEX_START + i * 2, meta.swapped) else {
                        entries.push(None);
                        continue;
                    };
                    let off = off as usize;
                    let Some(&kind) = p.get(off + 2) else {
                        entries.push(None);
                        continue;
                    };
                    let Ok(len) = read_u16(p, off, meta.swapped) else {
                        entries.push(None);
                        continue;
                    };

                    let item = match kind {
                        ENTRY_KEYDATA => p.get(off + 3..off + 3 + len as usize).map(<[u8]>::to_vec),
                        ENTRY_OVERFLOW => {
                            let Ok(pgno) = read_u32(p, off + 4, meta.swapped) else {
                                entries.push(None);
                                continue;
                            };
                            let Ok(tlen) = read_u32(p, off + 8, meta.swapped) else {
                                entries.push(None);
                                continue;
                            };
                            let mut seen = BTreeSet::new();
                            read_overflow(bytes, meta, pgno, tlen, &mut seen).ok()
                        }
                        _ => None,
                    };

                    entries.push(item);
                }
                for pair in entries.chunks(2) {
                    if let [Some(k), Some(v)] = pair {
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
    let mut budget = MAX_PAGES_VISITED;

    let mut top = Vec::new();
    walk_from(
        bytes,
        &meta,
        meta.root_page,
        &mut BTreeSet::new(),
        &mut budget,
        &mut top,
    );

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
        if out.len() >= MAX_RECORDS || budget == 0 {
            break;
        }
        // Each subdatabase gets its own `visited` set: a root that
        // collides with a page number touched elsewhere (by another
        // sub-tree, or by the master-level walk above) must not cause
        // this sub-tree to be skipped as "already visited".
        walk_from(
            bytes,
            &meta,
            root,
            &mut BTreeSet::new(),
            &mut budget,
            &mut out,
        );
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
    fn a_bad_leaf_entry_does_not_misalign_its_neighbours() {
        // Four leaf entries meant to pair as (AAAA,BBBB),(CCCC,DDDD). Entry 1
        // (BBBB) is corrupted: its index-table offset points past the end
        // of the page, so reading it fails. Compacting the survivors before
        // pairing (`chunks_exact` over only the successful reads) would
        // fuse AAAA — a real key — to CCCC, another key, as though it were
        // AAAA's value, and silently drop DDDD. Slot-preserving pairing
        // must instead drop only the (AAAA,BBBB) pair and keep (CCCC,DDDD).
        let page_size = 512u32;
        let mut v = meta_page(page_size, 1, 1);
        let base = page_size as usize; // page 1
        v[base + OFF_PAGE_TYPE] = PAGE_TYPE_LBTREE;
        v[base + OFF_ENTRY_COUNT..base + OFF_ENTRY_COUNT + 2].copy_from_slice(&4u16.to_le_bytes());

        let off_a: u16 = 34;
        let off_b: u16 = 5000; // corrupted: past the end of a 512-byte page.
        let off_c: u16 = 41;
        let off_d: u16 = 48;
        for (i, off) in [off_a, off_b, off_c, off_d].into_iter().enumerate() {
            let idx = base + OFF_INDEX_START + i * 2;
            v[idx..idx + 2].copy_from_slice(&off.to_le_bytes());
        }

        for (off, tag) in [(off_a, *b"AAAA"), (off_c, *b"CCCC"), (off_d, *b"DDDD")] {
            let start = base + off as usize;
            v[start..start + 2].copy_from_slice(&4u16.to_le_bytes());
            v[start + 2] = ENTRY_KEYDATA;
            v[start + 3..start + 7].copy_from_slice(&tag);
        }

        let pairs = walk(&v).unwrap();
        assert!(
            !pairs.iter().any(|(k, val)| k == b"AAAA" && val == b"CCCC"),
            "leaf entry desync: AAAA paired with CCCC instead of \
             being dropped along with its own corrupted neighbour: {pairs:?}"
        );
        // The trailing, uncorrupted pair must survive intact.
        assert!(
            pairs.iter().any(|(k, val)| k == b"CCCC" && val == b"DDDD"),
            "CCCC/DDDD pair lost even though neither entry was corrupted: {pairs:?}"
        );
    }

    #[test]
    fn a_subdb_root_colliding_with_the_master_walk_still_yields_records() {
        // Page 1 is the master-db leaf: it holds a "db" -> page-2 pointer
        // (which resolves through page 2's meta fields to root page 1 —
        // itself, simulating a crafted or corrupted root collision) plus an
        // unrelated real record. With a `visited` set shared between the
        // master-level walk and the subdatabase walk, page 1 is already
        // marked visited by the time the subdatabase walk tries to read it
        // again, so the whole subdatabase — including the real record — is
        // silently skipped and `walk` returns zero records.
        let page_size = 512u32;
        let mut v = meta_page(page_size, 2, 1);

        let base1 = page_size as usize; // page 1: master-db leaf
        v[base1 + OFF_PAGE_TYPE] = PAGE_TYPE_LBTREE;
        v[base1 + OFF_ENTRY_COUNT..base1 + OFF_ENTRY_COUNT + 2]
            .copy_from_slice(&4u16.to_le_bytes());

        let off0: u16 = 34; // "db"
        let off1: u16 = 39; // pgno 2, LE
        let off2: u16 = 46; // "realkey"
        let off3: u16 = 56; // "realvalue"
        for (i, off) in [off0, off1, off2, off3].into_iter().enumerate() {
            let idx = base1 + OFF_INDEX_START + i * 2;
            v[idx..idx + 2].copy_from_slice(&off.to_le_bytes());
        }

        let mut put = |off: u16, kind: u8, data: &[u8]| {
            let start = base1 + off as usize;
            v[start..start + 2].copy_from_slice(&(data.len() as u16).to_le_bytes());
            v[start + 2] = kind;
            v[start + 3..start + 3 + data.len()].copy_from_slice(data);
        };
        put(off0, ENTRY_KEYDATA, b"db");
        put(off1, ENTRY_KEYDATA, &2u32.to_le_bytes());
        put(off2, ENTRY_KEYDATA, b"realkey");
        put(off3, ENTRY_KEYDATA, b"realvalue");

        // Page 2: a subdatabase meta page whose root points back at page 1.
        let base2 = 2 * page_size as usize;
        v[base2 + 12..base2 + 16].copy_from_slice(&BDB_BTREE_MAGIC.to_le_bytes());
        v[base2 + 88..base2 + 92].copy_from_slice(&1u32.to_le_bytes());

        let pairs = walk(&v).unwrap();
        assert!(
            pairs
                .iter()
                .any(|(k, val)| k == b"realkey" && val == b"realvalue"),
            "subdatabase root colliding with the master walk lost its records: {pairs:?}"
        );
    }

    #[test]
    fn golden_fixtures_yield_the_expected_record_counts() {
        // Independently confirmed by two separate implementations. If a
        // change to the walker moves either number, that change broke
        // correct behaviour — the fixtures are ground truth, not the code.
        let expected = [("sprout-plaintext", 325), ("sprout-encrypted", 331)];
        for (name, want) in expected {
            let bytes = std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap();
            let pairs = walk(&bytes).unwrap();
            assert_eq!(pairs.len(), want, "{name}: record count changed");
        }
    }

    /// Write one `P_OVERFLOW` page into `v` at page `page`, carrying
    /// `payload` and chaining to `next`.
    ///
    /// **This page is hand-built, not captured from a real wallet.** None of
    /// the golden `wallet.dat` fixtures in `tests/fixtures/` contains a
    /// value large enough to overflow, so there is no real-world artifact to
    /// test against and one is constructed here instead. It is laid out to
    /// the Berkeley DB 6.2.32 `PAGE` header documented in
    /// `src/dbinc/db_page.h` — `lsn` 0-7, `pgno` 8-11, `prev_pgno` 12-15,
    /// `next_pgno` 16-19, `entries` 20-21, `hf_offset` 22-23, `level` 24,
    /// `type` 25, payload from `SIZEOF_PAGE` (26) — with the `P_OVERFLOW`
    /// overloading of those last two 16-bit fields (`OV_LEN` = `hf_offset`,
    /// `OV_REF` = `entries`) and with `OV_REF` set to 1, which is what
    /// `db_overflow.c` `__db_poff` writes.
    ///
    /// What a test over this proves: that `read_overflow` reads the byte
    /// count from the field the format specifies, and reassembles a
    /// multi-page chain in order. What it does **not** prove: that a real
    /// zcashd-written `wallet.dat` containing an overflowing record round
    /// trips through `walk`. Only a captured fixture could show that, and
    /// none exists.
    fn put_overflow_page(v: &mut [u8], page_size: u32, page: u32, next: u32, payload: &[u8]) {
        let base = (page as usize) * (page_size as usize);
        // pgno, then next_pgno — the field that chains the pages together.
        v[base + 8..base + 12].copy_from_slice(&page.to_le_bytes());
        v[base + 16..base + 20].copy_from_slice(&next.to_le_bytes());
        // OV_REF: the vestigial reference count, always 1. This is the field
        // the buggy code read as a length.
        v[base + OFF_ENTRY_COUNT..base + OFF_ENTRY_COUNT + 2].copy_from_slice(&1u16.to_le_bytes());
        // OV_LEN: the real payload byte count for this page.
        v[base + OFF_OVERFLOW_LEN..base + OFF_OVERFLOW_LEN + 2]
            .copy_from_slice(&(payload.len() as u16).to_le_bytes());
        v[base + OFF_PAGE_TYPE] = PAGE_TYPE_OVERFLOW;
        v[base + SIZEOF_PAGE..base + SIZEOF_PAGE + payload.len()].copy_from_slice(payload);
    }

    #[test]
    fn an_overflow_chain_reassembles_the_whole_value() {
        // A value split across two overflow pages. See put_overflow_page for
        // what this hand-built layout does and does not establish.
        //
        // The regression: the payload byte count lives in `hf_offset`
        // (offset 22), not `entries` (offset 20). Reading offset 20 gets
        // OV_REF — a constant 1 — so each page contributes a single byte and
        // the reassembled value is silently truncated garbage rather than
        // the record zcashd wrote. Every byte here is distinct, so a
        // wrong-offset read cannot pass by coincidence.
        let page_size = 512u32;
        let first: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let second: Vec<u8> = (0..100u32).map(|i| (i % 241 + 3) as u8).collect();
        let expected: Vec<u8> = first.iter().chain(second.iter()).copied().collect();

        let mut v = meta_page(page_size, 3, 1);
        put_overflow_page(&mut v, page_size, 2, 3, &first);
        put_overflow_page(&mut v, page_size, 3, 0, &second);

        let meta = read_meta(&v).unwrap();
        let got = read_overflow(
            &v,
            &meta,
            2,
            expected.len() as u32,
            &mut std::collections::BTreeSet::new(),
        )
        .expect("a well-formed overflow chain must reassemble");

        assert_eq!(
            got.len(),
            expected.len(),
            "overflow chain reassembled {} bytes, expected {}",
            got.len(),
            expected.len()
        );
        assert_eq!(
            got, expected,
            "overflow chain reassembled the wrong bytes: the per-page length \
             must come from hf_offset (offset 22), not entries (offset 20)"
        );
    }

    #[test]
    fn an_overflow_value_reaches_walk_as_one_record() {
        // The same reassembly, but driven through the public entry point:
        // a leaf page whose value entry is a B_OVERFLOW (`unused1:u16,
        // type:u8, unused2:u8, pgno:u32, tlen:u32` — db_page.h `BOVERFLOW`)
        // pointing at the chain. Hand-built; see put_overflow_page.
        let page_size = 512u32;
        let payload: Vec<u8> = (0..600u32).map(|i| (i % 253 + 1) as u8).collect();
        let mut v = meta_page(page_size, 4, 1);

        // Page 1: a leaf with one (key, value) pair.
        let base = page_size as usize;
        v[base + OFF_PAGE_TYPE] = PAGE_TYPE_LBTREE;
        v[base + OFF_ENTRY_COUNT..base + OFF_ENTRY_COUNT + 2].copy_from_slice(&2u16.to_le_bytes());

        let off_key: u16 = 34;
        let off_val: u16 = 48;
        for (i, off) in [off_key, off_val].into_iter().enumerate() {
            let idx = base + OFF_INDEX_START + i * 2;
            v[idx..idx + 2].copy_from_slice(&off.to_le_bytes());
        }

        // Key: an ordinary B_KEYDATA entry (len:u16, type:u8, data...).
        let key = b"bigvalue";
        let ks = base + off_key as usize;
        v[ks..ks + 2].copy_from_slice(&(key.len() as u16).to_le_bytes());
        v[ks + 2] = ENTRY_KEYDATA;
        v[ks + 3..ks + 3 + key.len()].copy_from_slice(key);

        // Value: a B_OVERFLOW entry pointing at page 3.
        let vs = base + off_val as usize;
        v[vs + 2] = ENTRY_OVERFLOW;
        v[vs + 4..vs + 8].copy_from_slice(&3u32.to_le_bytes()); // pgno
        v[vs + 8..vs + 12].copy_from_slice(&(payload.len() as u32).to_le_bytes()); // tlen

        put_overflow_page(&mut v, page_size, 3, 4, &payload[..400]);
        put_overflow_page(&mut v, page_size, 4, 0, &payload[400..]);

        let pairs = walk(&v).unwrap();
        assert!(
            pairs.iter().any(|(k, val)| k == key && *val == payload),
            "an overflowing value must reach the caller intact; got {:?}",
            pairs
                .iter()
                .map(|(k, val)| (String::from_utf8_lossy(k).into_owned(), val.len()))
                .collect::<Vec<_>>()
        );
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
