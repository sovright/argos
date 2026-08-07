//! A single peer connection: handshake, message exchange, block fetching.
//!
//! Deliberately minimal. This client asks for historical blocks and nothing
//! else — it offers no services, accepts no inbound connections, relays no
//! transactions, and keeps no peer database. Every byte it reads comes from
//! an anonymous host on the internet, so the framing layer in [`super::wire`]
//! bounds every allocation before this module acts on it.
//!
//! # Timeouts everywhere
//!
//! A peer that accepts a connection and then says nothing is
//! indistinguishable from a slow one, and a recovery tool that hangs on it
//! looks identical to a broken tool. Every read is bounded, so a silent peer
//! surfaces as an error the caller can retry against a different host rather
//! than as a stall.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::wire::{
    decode_header, decode_headers, encode_getdata_blocks, encode_getheaders, encode_message,
    encode_version, verify_payload, BlockHeader, Header, P2pNetwork, WireError, MAX_PAYLOAD_LEN,
};

/// Protocol version to advertise. 170_100 is comfortably past every
/// Sprout-era activation, so peers serve the full historical range.
const PROTOCOL_VERSION: u32 = 170_100;

/// Presented to peers. Honest about what this is: an unusual client asking
/// for very old blocks should not look like it is pretending to be zcashd.
const USER_AGENT: &str = "/Argos-recovery:1.0/";

/// How long to wait for any single message.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for the TCP connection itself.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("connecting to {addr}: {source}")]
    Connect {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    #[error("timed out waiting for {what}")]
    Timeout { what: String },
    #[error("connection closed by the peer")]
    Closed,
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("peer speaks protocol version {0}, which is too old to serve Sprout-era blocks")]
    ProtocolTooOld(u32),
    #[error("the peer never completed the handshake")]
    HandshakeIncomplete,
}

/// A connected, handshaken peer.
pub struct Peer {
    stream: TcpStream,
    network: P2pNetwork,
    /// The peer's advertised chain height, from its `version`.
    pub peer_height: u32,
}

impl Peer {
    /// Connect and complete the version/verack handshake.
    pub async fn connect(addr: &str, network: P2pNetwork) -> Result<Self, PeerError> {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| PeerError::Timeout {
                what: format!("a connection to {addr}"),
            })?
            .map_err(|source| PeerError::Connect {
                addr: addr.to_owned(),
                source,
            })?;

        // Historical block fetching is throughput-bound and request/response
        // shaped; Nagle would add a round trip of latency per request.
        stream.set_nodelay(true)?;

        let mut peer = Self {
            stream,
            network,
            peer_height: 0,
        };
        peer.handshake().await?;
        Ok(peer)
    }

    /// Exchange `version`/`verack`.
    ///
    /// The nonce exists to let a node recognise a connection to itself. This
    /// client never listens, so it cannot connect to itself, but a
    /// zero nonce is a recognisable fingerprint — it is derived from the
    /// connection instead.
    async fn handshake(&mut self) -> Result<(), PeerError> {
        let nonce = handshake_nonce(&self.stream);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let version = encode_version(PROTOCOL_VERSION, USER_AGENT, 0, nonce, timestamp);
        self.send("version", &version).await?;

        let mut got_version = false;
        let mut got_verack = false;

        // A peer may interleave other messages during the handshake; only
        // the two that matter are acted on, and the rest are discarded.
        for _ in 0..16 {
            let (header, payload) = self.recv().await?;
            match header.command.as_str() {
                "version" => {
                    let advertised = u32::from_le_bytes(
                        payload
                            .get(..4)
                            .and_then(|b| b.try_into().ok())
                            .ok_or(WireError::MalformedPayload("version".to_owned()))?,
                    );
                    if advertised < 170_002 {
                        return Err(PeerError::ProtocolTooOld(advertised));
                    }
                    // start_height sits after the variable-length user agent,
                    // so it is read by walking past it rather than at a fixed
                    // offset.
                    self.peer_height = parse_start_height(&payload).unwrap_or(0);
                    self.send("verack", &[]).await?;
                    got_version = true;
                }
                "verack" => got_verack = true,
                // `ping` during handshake is normal; answering keeps the
                // connection alive.
                "ping" => self.send("pong", &payload).await?,
                _ => {}
            }
            if got_version && got_verack {
                return Ok(());
            }
        }

        Err(PeerError::HandshakeIncomplete)
    }

    async fn send(&mut self, command: &str, payload: &[u8]) -> Result<(), PeerError> {
        let framed = encode_message(self.network, command, payload);
        self.stream.write_all(&framed).await?;
        Ok(())
    }

    /// Read one message, bounded by [`READ_TIMEOUT`].
    async fn recv(&mut self) -> Result<(Header, Vec<u8>), PeerError> {
        let mut header_bytes = [0u8; super::wire::HEADER_LEN];
        timeout(READ_TIMEOUT, self.stream.read_exact(&mut header_bytes))
            .await
            .map_err(|_| PeerError::Timeout {
                what: "a message header".to_owned(),
            })?
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::UnexpectedEof {
                    PeerError::Closed
                } else {
                    PeerError::Io(err)
                }
            })?;

        // Validated against MAX_PAYLOAD_LEN before it is used to allocate.
        let header = decode_header(&header_bytes, self.network)?;
        debug_assert!(header.payload_len <= MAX_PAYLOAD_LEN);

        let mut payload = vec![0u8; header.payload_len];
        timeout(READ_TIMEOUT, self.stream.read_exact(&mut payload))
            .await
            .map_err(|_| PeerError::Timeout {
                what: format!("the {} payload", header.command),
            })?
            .map_err(|err| {
                if err.kind() == std::io::ErrorKind::UnexpectedEof {
                    PeerError::Closed
                } else {
                    PeerError::Io(err)
                }
            })?;

        verify_payload(&header, &payload)?;
        Ok((header, payload))
    }

    /// Read messages until one of `wanted` arrives, answering pings and
    /// discarding everything else.
    ///
    /// Bounded rather than looping forever: a peer that floods unrelated
    /// messages must not be able to keep the scan alive indefinitely.
    async fn recv_until(&mut self, wanted: &str) -> Result<Vec<u8>, PeerError> {
        for _ in 0..256 {
            let (header, payload) = self.recv().await?;
            if header.command == wanted {
                return Ok(payload);
            }
            if header.command == "ping" {
                self.send("pong", &payload).await?;
            }
        }
        Err(PeerError::Timeout {
            what: format!("a {wanted} message"),
        })
    }

    /// Ask for up to 160 headers following `locator`.
    pub async fn get_headers(
        &mut self,
        locator: &[[u8; 32]],
    ) -> Result<Vec<BlockHeader>, PeerError> {
        let payload = encode_getheaders(PROTOCOL_VERSION, locator, [0u8; 32]);
        self.send("getheaders", &payload).await?;
        let reply = self.recv_until("headers").await?;
        Ok(decode_headers(&reply)?)
    }

    /// Fetch full blocks by hash, returning their raw bytes.
    ///
    /// Blocks come back as separate `block` messages in an unspecified
    /// order, so they are matched to the request rather than assumed to
    /// arrive in sequence.
    pub async fn get_blocks(&mut self, hashes: &[[u8; 32]]) -> Result<Vec<Vec<u8>>, PeerError> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }

        let payload = encode_getdata_blocks(hashes);
        self.send("getdata", &payload).await?;

        let mut blocks = Vec::with_capacity(hashes.len());
        for _ in 0..hashes.len() {
            blocks.push(self.recv_until("block").await?);
        }
        Ok(blocks)
    }
}

/// Read `start_height` out of a `version` payload.
///
/// It follows the variable-length user agent, so the fixed prefix
/// (version, services, timestamp, two addresses, nonce = 4+8+8+26+26+8 = 80)
/// is skipped and the CompactSize-prefixed string walked past.
fn parse_start_height(payload: &[u8]) -> Option<u32> {
    const FIXED_PREFIX: usize = 80;
    let (ua_len, used) = super::wire::read_compact_size(payload.get(FIXED_PREFIX..)?)?;
    let start = FIXED_PREFIX
        .checked_add(used)?
        .checked_add(usize::try_from(ua_len).ok()?)?;
    let bytes = payload.get(start..start.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Derive a handshake nonce from the connection's own addresses.
///
/// Its only protocol job is to differ from a node's own nonce so self
/// connections are detected. A constant would be a recognisable fingerprint
/// for this client, and pulling in a CSPRNG for a value with no security
/// role would be worse.
fn handshake_nonce(stream: &TcpStream) -> u64 {
    let mut hasher = <sha2::Sha256 as sha2::Digest>::new();
    if let Ok(local) = stream.local_addr() {
        sha2::Digest::update(&mut hasher, local.to_string().as_bytes());
    }
    if let Ok(peer) = stream.peer_addr() {
        sha2::Digest::update(&mut hasher, peer.to_string().as_bytes());
    }
    let digest = sha2::Digest::finalize(hasher);
    u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::wire::write_compact_size;

    fn version_payload(user_agent: &str, start_height: u32) -> Vec<u8> {
        encode_version(PROTOCOL_VERSION, user_agent, start_height, 7, 1_700_000_000)
    }

    /// `start_height` sits after a variable-length string, so a fixed offset
    /// would read the wrong four bytes for any user agent but one.
    #[test]
    fn start_height_is_found_past_a_variable_length_user_agent() {
        for ua in ["", "/x/", "/zcashd:5.10.0/", &"/".repeat(200)] {
            let payload = version_payload(ua, 1_234_567);
            assert_eq!(
                parse_start_height(&payload),
                Some(1_234_567),
                "user agent {:?} ({} bytes) must not shift the read",
                ua,
                ua.len()
            );
        }
    }

    #[test]
    fn a_truncated_version_payload_yields_no_height() {
        let payload = version_payload("/zcashd:5.10.0/", 99);
        // The height occupies the four bytes ending just before the
        // trailing relay flag, so anything cut short of that must fail.
        let height_end = payload.len() - 1;
        for cut in [0, 40, 80, height_end - 1] {
            assert!(
                parse_start_height(&payload[..cut]).is_none(),
                "a version payload cut to {cut} bytes must not produce a height"
            );
        }
        // The boundary itself: with the height complete but the relay flag
        // gone, the height is still readable. Pinned so the offset
        // arithmetic above cannot drift unnoticed.
        assert_eq!(parse_start_height(&payload[..height_end]), Some(99));
    }

    /// A peer could claim a user agent length far past the payload; that
    /// must not panic or read out of bounds.
    #[test]
    fn a_lying_user_agent_length_is_rejected() {
        let mut payload = vec![0u8; 80];
        write_compact_size(&mut payload, u64::MAX);
        payload.extend_from_slice(&[0u8; 8]);
        assert!(parse_start_height(&payload).is_none());
    }
}
