//! Read-only Berkeley DB 6.2 btree walker.
//!
//! Knows nothing about Zcash: it yields raw `(key, value)` byte pairs.
//! Every offset here is attacker-controlled, so all reads go through
//! `get()` and every length is bounds-checked before it is used to size
//! an allocation.

use crate::error::ImportError;

const BDB_BTREE_MAGIC: u32 = 0x0005_3162;

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
    let slice = bytes
        .get(offset..offset + 4)
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
///
/// Unused by this task; the btree walker (Task 5) consumes it for cell
/// and index entries.
#[allow(dead_code)]
pub(crate) fn read_u16(bytes: &[u8], offset: usize, swapped: bool) -> Result<u16, ImportError> {
    let slice = bytes
        .get(offset..offset + 2)
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
    fn reads_real_golden_fixtures() {
        for name in ["sprout-plaintext", "modern-encrypted"] {
            let bytes = std::fs::read(format!("tests/fixtures/{name}.dat")).unwrap();
            let m = read_meta(&bytes).unwrap();
            assert!(m.page_size.is_power_of_two(), "{name}: {}", m.page_size);
            assert!(m.page_size >= MIN_PAGE_SIZE && m.page_size <= MAX_PAGE_SIZE);
        }
    }
}
