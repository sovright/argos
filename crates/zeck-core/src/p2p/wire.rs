//! Zcash peer-to-peer message framing.
//!
//! Sprout notes cannot be found over lightwalletd. Compact blocks carry
//! Sapling and Orchard outputs only, and `TreeState` exposes a Sapling and
//! an Orchard tree and no Sprout one — so a JoinSplit never appears in that
//! stream at all, at any level of client effort. Finding a Sprout note means
//! reading full blocks, and this module is the wire format for asking the
//! network directly.
//!
//! # Why the scan is finite
//!
//! ZIP 211 disables adding value to the Sprout pool from Canopy activation
//! onward. Every Sprout note that will ever exist was therefore created
//! below that height, so the range this scanner must cover is closed and
//! never grows — unlike a Sapling or Orchard scan, which chases the tip.
//!
//! # Scope
//!
//! Framing only: encoding and decoding message headers and the handful of
//! payloads the block sweep needs. Everything here is pure and synchronous
//! so it can be tested without a socket, which is the point — a framing bug
//! against a live peer shows up as a stall or a disconnect, with nothing to
//! inspect.
//!
//! Bytes arriving here come from an anonymous peer on the internet, so every
//! decode is bounds-checked and every length is validated against a cap
//! before it is used to size an allocation.

use sha2::{Digest, Sha256};

/// Longest payload accepted from a peer, matching zcashd's
/// `MAX_PROTOCOL_MESSAGE_LENGTH`. A peer that claims more is not answered;
/// the length field arrives before the payload, so this is checked before
/// anything is allocated.
pub const MAX_PAYLOAD_LEN: usize = 2 * 1024 * 1024;

/// Message header: magic(4) + command(12) + length(4) + checksum(4).
pub const HEADER_LEN: usize = 24;

const COMMAND_LEN: usize = 12;

/// Network magic, distinguishing mainnet/testnet/regtest traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P2pNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl P2pNetwork {
    pub const fn magic(self) -> [u8; 4] {
        match self {
            Self::Mainnet => [0x24, 0xe9, 0x27, 0x64],
            Self::Testnet => [0xfa, 0x1a, 0xf9, 0xbf],
            Self::Regtest => [0xaa, 0xe8, 0x3f, 0x5f],
        }
    }

    /// The height at which Canopy activates, and so the exclusive upper
    /// bound of any Sprout scan: ZIP 211 forbids adding to the Sprout pool
    /// from here on, so no Sprout note is ever created at or above it.
    pub const fn sprout_scan_end(self) -> u32 {
        match self {
            Self::Mainnet => 1_046_400,
            Self::Testnet => 1_028_500,
            // Regtest activates whatever the config says; callers that need
            // a real bound there pass it explicitly.
            Self::Regtest => u32::MAX,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    #[error("message is shorter than a header")]
    Truncated,
    #[error("network magic {got:02x?} does not match the expected {want:02x?}")]
    WrongMagic { got: [u8; 4], want: [u8; 4] },
    #[error("command name is not valid ASCII")]
    BadCommand,
    #[error("payload length {0} exceeds the protocol maximum")]
    PayloadTooLong(usize),
    #[error("checksum mismatch: the payload does not match its header")]
    BadChecksum,
    #[error("payload is malformed for command {0}")]
    MalformedPayload(String),
}

/// Bitcoin-style double SHA-256, used for both the message checksum and
/// block hashing.
pub fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

fn checksum(payload: &[u8]) -> [u8; 4] {
    let hash = sha256d(payload);
    let mut out = [0u8; 4];
    out.copy_from_slice(&hash[..4]);
    out
}

/// A decoded message header. The payload follows in the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub command: String,
    pub payload_len: usize,
    pub checksum: [u8; 4],
}

/// Frame a payload for the wire.
pub fn encode_message(network: P2pNetwork, command: &str, payload: &[u8]) -> Vec<u8> {
    debug_assert!(command.len() <= COMMAND_LEN, "command name too long");

    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&network.magic());

    let mut name = [0u8; COMMAND_LEN];
    let bytes = command.as_bytes();
    let n = bytes.len().min(COMMAND_LEN);
    name[..n].copy_from_slice(&bytes[..n]);
    out.extend_from_slice(&name);

    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&checksum(payload));
    out.extend_from_slice(payload);
    out
}

/// Decode a header, rejecting anything that would be unsafe to act on.
///
/// The length cap is enforced here rather than at the read site so that no
/// caller can be tricked into allocating from a peer-supplied length.
pub fn decode_header(bytes: &[u8], network: P2pNetwork) -> Result<Header, WireError> {
    let bytes = bytes.get(..HEADER_LEN).ok_or(WireError::Truncated)?;

    let magic: [u8; 4] = bytes[..4].try_into().expect("4 bytes");
    if magic != network.magic() {
        return Err(WireError::WrongMagic {
            got: magic,
            want: network.magic(),
        });
    }

    let name = &bytes[4..4 + COMMAND_LEN];
    let end = name.iter().position(|b| *b == 0).unwrap_or(COMMAND_LEN);
    let command = std::str::from_utf8(&name[..end])
        .map_err(|_| WireError::BadCommand)?
        .to_owned();
    if !command.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(WireError::BadCommand);
    }

    let payload_len = u32::from_le_bytes(bytes[16..20].try_into().expect("4 bytes")) as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(WireError::PayloadTooLong(payload_len));
    }

    let checksum: [u8; 4] = bytes[20..24].try_into().expect("4 bytes");

    Ok(Header {
        command,
        payload_len,
        checksum,
    })
}

/// Confirm a payload matches the checksum its header advertised.
pub fn verify_payload(header: &Header, payload: &[u8]) -> Result<(), WireError> {
    if payload.len() != header.payload_len || checksum(payload) != header.checksum {
        return Err(WireError::BadChecksum);
    }
    Ok(())
}

/// Bitcoin-style CompactSize.
pub fn write_compact_size(out: &mut Vec<u8>, value: u64) {
    match value {
        0..=0xFC => out.push(value as u8),
        0xFD..=0xFFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFE);
            out.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
}

/// Read a CompactSize, returning the value and how many bytes it used.
pub fn read_compact_size(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    match first {
        0..=0xFC => Some((u64::from(first), 1)),
        0xFD => {
            let v = u16::from_le_bytes(bytes.get(1..3)?.try_into().ok()?);
            Some((u64::from(v), 3))
        }
        0xFE => {
            let v = u32::from_le_bytes(bytes.get(1..5)?.try_into().ok()?);
            Some((u64::from(v), 5))
        }
        _ => {
            let v = u64::from_le_bytes(bytes.get(1..9)?.try_into().ok()?);
            Some((v, 9))
        }
    }
}

/// Build a `version` payload.
///
/// The addresses are advertised as unroutable zeros: this client never
/// accepts inbound connections, and telling the network otherwise would be
/// both false and a privacy leak.
pub fn encode_version(
    protocol_version: u32,
    user_agent: &str,
    start_height: u32,
    nonce: u64,
    timestamp: i64,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&protocol_version.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes()); // services: none offered
    out.extend_from_slice(&timestamp.to_le_bytes());
    out.extend_from_slice(&[0u8; 26]); // addr_recv
    out.extend_from_slice(&[0u8; 26]); // addr_from
    out.extend_from_slice(&nonce.to_le_bytes());

    let ua = user_agent.as_bytes();
    write_compact_size(&mut out, ua.len() as u64);
    out.extend_from_slice(ua);

    out.extend_from_slice(&start_height.to_le_bytes());
    // relay=false: this client wants historical blocks, not the mempool
    // firehose.
    out.push(0x00);
    out
}

/// Inventory type for a block, per `MSG_BLOCK`.
pub const INV_BLOCK: u32 = 2;

/// Build a `getdata` payload requesting full blocks by hash.
pub fn encode_getdata_blocks(hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::new();
    write_compact_size(&mut out, hashes.len() as u64);
    for hash in hashes {
        out.extend_from_slice(&INV_BLOCK.to_le_bytes());
        out.extend_from_slice(hash);
    }
    out
}

/// Build a `getheaders` payload.
///
/// `locator` runs newest-first; the peer replies with headers following the
/// first entry it recognises, which is what makes the walk resilient to a
/// reorg partway through.
pub fn encode_getheaders(protocol_version: u32, locator: &[[u8; 32]], stop: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&protocol_version.to_le_bytes());
    write_compact_size(&mut out, locator.len() as u64);
    for hash in locator {
        out.extend_from_slice(hash);
    }
    out.extend_from_slice(&stop);
    out
}

/// A block header as it appears on the wire, kept as raw bytes plus its
/// hash. The scanner needs the hash to request the block and the previous
/// hash to verify the chain links up; nothing else here is interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub hash: [u8; 32],
    pub prev_hash: [u8; 32],
}

/// Zcash block header length. Unlike Bitcoin's 80, Zcash carries
/// `hashFinalSaplingRoot`(32) and a 32-byte `nonce` plus the Equihash
/// solution, so the fixed part is 140 bytes and the solution follows as a
/// CompactSize-prefixed blob.
const HEADER_FIXED_LEN: usize = 140;

/// Decode a `headers` payload.
///
/// Each entry is a full block header followed by a CompactSize transaction
/// count, which is always zero in a `headers` message.
pub fn decode_headers(payload: &[u8]) -> Result<Vec<BlockHeader>, WireError> {
    let malformed = || WireError::MalformedPayload("headers".to_owned());

    let (count, mut pos) = read_compact_size(payload).ok_or_else(malformed)?;
    // Each header is >= 141 bytes, so a count that could not possibly fit
    // is rejected before it sizes an allocation.
    if count > (payload.len() / HEADER_FIXED_LEN) as u64 {
        return Err(malformed());
    }

    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let fixed = payload
            .get(pos..pos + HEADER_FIXED_LEN)
            .ok_or_else(malformed)?;
        let prev_hash: [u8; 32] = fixed.get(4..36).ok_or_else(malformed)?.try_into().unwrap();

        let (solution_len, used) = read_compact_size(
            payload
                .get(pos + HEADER_FIXED_LEN..)
                .ok_or_else(malformed)?,
        )
        .ok_or_else(malformed)?;
        let solution_len = usize::try_from(solution_len).map_err(|_| malformed())?;

        let header_end = pos
            .checked_add(HEADER_FIXED_LEN)
            .and_then(|v| v.checked_add(used))
            .and_then(|v| v.checked_add(solution_len))
            .ok_or_else(malformed)?;
        let header_bytes = payload.get(pos..header_end).ok_or_else(malformed)?;

        out.push(BlockHeader {
            hash: sha256d(header_bytes),
            prev_hash,
        });

        // The trailing transaction count, always zero here.
        let (_, tx_count_len) = read_compact_size(payload.get(header_end..).ok_or_else(malformed)?)
            .ok_or_else(malformed)?;
        pos = header_end.checked_add(tx_count_len).ok_or_else(malformed)?;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_framed_message_round_trips() {
        let payload = b"hello sprout".to_vec();
        let framed = encode_message(P2pNetwork::Mainnet, "version", &payload);

        let header = decode_header(&framed, P2pNetwork::Mainnet).expect("header must decode");
        assert_eq!(header.command, "version");
        assert_eq!(header.payload_len, payload.len());
        verify_payload(&header, &payload).expect("checksum must verify");
        assert_eq!(&framed[HEADER_LEN..], &payload[..]);
    }

    /// The framing check that matters: a payload altered in flight must be
    /// rejected rather than parsed.
    #[test]
    fn a_corrupted_payload_fails_its_checksum() {
        let payload = b"hello sprout".to_vec();
        let framed = encode_message(P2pNetwork::Mainnet, "block", &payload);
        let header = decode_header(&framed, P2pNetwork::Mainnet).unwrap();

        let mut corrupted = payload.clone();
        corrupted[0] ^= 0xFF;
        assert_eq!(
            verify_payload(&header, &corrupted),
            Err(WireError::BadChecksum)
        );

        // A truncated payload must fail too, not read short.
        assert_eq!(
            verify_payload(&header, &payload[..payload.len() - 1]),
            Err(WireError::BadChecksum)
        );
    }

    /// Connecting to a testnet peer with mainnet magic must fail loudly at
    /// the first message rather than silently scan the wrong chain.
    #[test]
    fn a_message_from_the_wrong_network_is_rejected() {
        let framed = encode_message(P2pNetwork::Testnet, "version", b"");
        let err = decode_header(&framed, P2pNetwork::Mainnet).unwrap_err();
        assert!(matches!(err, WireError::WrongMagic { .. }));
    }

    /// A peer-supplied length must never reach an allocation.
    #[test]
    fn an_oversized_payload_length_is_rejected_before_allocating() {
        let mut framed = encode_message(P2pNetwork::Mainnet, "block", b"");
        framed[16..20].copy_from_slice(&(MAX_PAYLOAD_LEN as u32 + 1).to_le_bytes());
        assert_eq!(
            decode_header(&framed, P2pNetwork::Mainnet),
            Err(WireError::PayloadTooLong(MAX_PAYLOAD_LEN + 1))
        );
    }

    #[test]
    fn a_truncated_header_is_rejected() {
        let framed = encode_message(P2pNetwork::Mainnet, "verack", b"");
        for cut in 0..HEADER_LEN {
            assert_eq!(
                decode_header(&framed[..cut], P2pNetwork::Mainnet),
                Err(WireError::Truncated)
            );
        }
    }

    /// A command name padded with garbage rather than nulls must not become
    /// a String full of control characters.
    #[test]
    fn a_non_ascii_command_is_rejected() {
        let mut framed = encode_message(P2pNetwork::Mainnet, "block", b"");
        framed[4..16].copy_from_slice(&[0xFF; 12]);
        assert!(matches!(
            decode_header(&framed, P2pNetwork::Mainnet),
            Err(WireError::BadCommand)
        ));
    }

    #[test]
    fn compact_size_round_trips_across_every_encoding_width() {
        for value in [
            0u64,
            0xFC,
            0xFD,
            0xFFFF,
            0x1_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
        ] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, value);
            let (decoded, used) = read_compact_size(&buf).expect("must decode");
            assert_eq!(decoded, value, "value {value} must round-trip");
            assert_eq!(used, buf.len(), "must consume exactly what it wrote");
        }
    }

    #[test]
    fn a_truncated_compact_size_is_rejected() {
        for value in [0xFDu64, 0x1_0000, 0x1_0000_0000] {
            let mut buf = Vec::new();
            write_compact_size(&mut buf, value);
            for cut in 1..buf.len() {
                assert!(
                    read_compact_size(&buf[..cut]).is_none(),
                    "a CompactSize truncated to {cut} bytes must be rejected"
                );
            }
        }
    }

    #[test]
    fn getdata_requests_blocks_by_hash() {
        let hashes = [[0x11u8; 32], [0x22u8; 32]];
        let payload = encode_getdata_blocks(&hashes);

        let (count, pos) = read_compact_size(&payload).unwrap();
        assert_eq!(count, 2);
        assert_eq!(
            u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap()),
            INV_BLOCK
        );
        assert_eq!(&payload[pos + 4..pos + 36], &[0x11u8; 32]);
        assert_eq!(payload.len(), pos + 2 * 36);
    }

    #[test]
    fn a_version_payload_advertises_no_services_and_no_relay() {
        let payload = encode_version(170_100, "/Argos:1.0/", 0, 42, 1_700_000_000);
        assert_eq!(
            u64::from_le_bytes(payload[4..12].try_into().unwrap()),
            0,
            "no services offered: this client never accepts inbound connections"
        );
        assert_eq!(
            *payload.last().unwrap(),
            0x00,
            "relay must be off; the scan wants history, not the mempool"
        );
    }

    /// Build a `headers` payload the way a peer would, so the decoder is
    /// checked against the real framing rather than its own idea of it.
    fn headers_payload(entries: &[([u8; 32], usize)]) -> Vec<u8> {
        let mut out = Vec::new();
        write_compact_size(&mut out, entries.len() as u64);
        for (prev, solution_len) in entries {
            let mut fixed = vec![0u8; HEADER_FIXED_LEN];
            fixed[4..36].copy_from_slice(prev);
            out.extend_from_slice(&fixed);
            write_compact_size(&mut out, *solution_len as u64);
            out.extend_from_slice(&vec![0xAB; *solution_len]);
            write_compact_size(&mut out, 0); // tx count, always 0 in headers
        }
        out
    }

    #[test]
    fn headers_decode_with_their_equihash_solution() {
        // 1344 is the mainnet Equihash solution size; the decoder must not
        // assume it, so a second entry uses a different length.
        let payload = headers_payload(&[([0x01; 32], 1344), ([0x02; 32], 100)]);
        let headers = decode_headers(&payload).expect("must decode");

        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].prev_hash, [0x01; 32]);
        assert_eq!(headers[1].prev_hash, [0x02; 32]);
        assert_ne!(
            headers[0].hash, headers[1].hash,
            "distinct headers must hash differently"
        );
    }

    #[test]
    fn a_truncated_headers_payload_is_rejected() {
        let payload = headers_payload(&[([0x01; 32], 1344)]);
        for cut in [1, 50, payload.len() - 1] {
            assert!(
                decode_headers(&payload[..cut]).is_err(),
                "headers truncated to {cut} bytes must be rejected"
            );
        }
    }

    /// A peer claiming more headers than the payload could hold must not
    /// cause a huge allocation.
    #[test]
    fn a_lying_header_count_is_rejected_before_allocating() {
        let mut payload = Vec::new();
        write_compact_size(&mut payload, u64::from(u32::MAX));
        payload.extend_from_slice(&[0u8; 200]);
        assert!(decode_headers(&payload).is_err());
    }

    /// ZIP 211 is what makes this scan finite; if the bound were ever wrong
    /// the scanner would either miss notes or run forever.
    #[test]
    fn the_sprout_scan_range_ends_at_canopy() {
        assert_eq!(P2pNetwork::Mainnet.sprout_scan_end(), 1_046_400);
        assert_eq!(P2pNetwork::Testnet.sprout_scan_end(), 1_028_500);
    }

    #[test]
    fn each_network_has_a_distinct_magic() {
        let magics = [
            P2pNetwork::Mainnet.magic(),
            P2pNetwork::Testnet.magic(),
            P2pNetwork::Regtest.magic(),
        ];
        for (i, a) in magics.iter().enumerate() {
            for b in magics.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }
}
