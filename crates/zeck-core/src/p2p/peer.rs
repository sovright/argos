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

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

use super::wire::{
    decode_header, decode_headers, encode_getdata_blocks, encode_getheaders, encode_message,
    encode_version, verify_payload, BlockHeader, Header, P2pNetwork, WireError, MAX_PAYLOAD_LEN,
};

/// Protocol version to advertise.
///
/// This is a *floor set by peers*, not a capability claim about us. ZIP 253
/// requires nodes compatible with an upgrade to advertise at least that
/// upgrade's `MIN_NETWORK_PROTOCOL_VERSION`, and peers disconnect anything
/// below it before the handshake completes — silently, with no message.
///
/// 170_160 is the NU6.3 (Ironwood) minimum for mainnet. Advertising the
/// Sprout-era-sufficient 170_100 instead is rejected by every current node:
/// confirmed directly from a peer's own metrics, which recorded
/// `remote_version="170100" min_version="170160"` against this client's user
/// agent. The failure looks identical to a network problem, so it must be
/// diagnosed from the far side.
///
/// Raise this when the network's minimum rises. Nothing here depends on the
/// value beyond being accepted — the blocks this scanner reads are two
/// decades of consensus older than any of it.
const PROTOCOL_VERSION: u32 = 170_160;

/// Presented to peers. Honest about what this is: an unusual client asking
/// for very old blocks should not look like it is pretending to be zcashd.
const USER_AGENT: &str = "/Argos-recovery:1.0/";

/// How long to wait for any single message.
///
/// Per message, not per request: a slow link that delivers a block at least
/// this often never trips it.
#[cfg(not(test))]
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Unit tests stand up fake peers that go silent on purpose, several per
/// test; thirty seconds each would make the suite crawl without testing
/// anything a shorter wait does not.
#[cfg(test)]
pub const READ_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a peer may go quiet, part-way through answering a `getdata`,
/// before the blocks it has not sent are asked for again.
///
/// Zebra can answer a batch with only some of the blocks and then nothing,
/// not even `notfound`: measured against Zebra 7.0.0 at mainnet heights
/// 9153..9168 (two of them about 744 KB), where 11 of 16 arrived. Its
/// replies to one request arrive back to back, so a pause this long after
/// some of them means it has stopped, not that it is slow. Only the wait
/// for the next message to begin is bounded; a large block still has
/// [`READ_TIMEOUT`] to arrive once it has started.
#[cfg(not(test))]
const PARTIAL_ANSWER_QUIET: Duration = Duration::from_secs(5);
#[cfg(test)]
const PARTIAL_ANSWER_QUIET: Duration = Duration::from_millis(200);

/// How long to wait for the TCP connection itself.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How many blocks to name in one `getdata`.
///
/// Peers do not answer a request for a whole 160-hash header page, so this
/// stays well under it. Small enough to be served reliably, large enough
/// that a million-block sweep is not a million round trips.
const GETDATA_BATCH: usize = 16;

/// The most blocks one page may name. What an honest `headers` reply holds;
/// a hostile one can list ~14,700, so callers truncate to this before asking
/// for bodies.
pub const MAX_PAGE_BLOCKS: usize = 160;

/// Zcash's consensus limit on a block's serialized size.
const MAX_BLOCK_BYTES: usize = 2_000_000;

/// Ceiling on the block bytes held from one `get_blocks` call.
///
/// Every batch's bodies accumulate in one map until the page is fetched, so
/// this is what one page may hold resident. Sized for a full page of
/// maximum-size blocks, because the scan now runs to the chain tip and the
/// 2022-23 spam era has pages near that: the earlier 256 MB, sized for
/// Sprout-era blocks of a few kilobytes, refused honest peers there on
/// every page.
const MAX_BLOCKS_BYTES: usize = MAX_PAGE_BLOCKS * MAX_BLOCK_BYTES;

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("connecting to {addr}: {source}")]
    Connect {
        addr: String,
        #[source]
        source: std::io::Error,
    },
    /// Connecting took too long. Only the TCP connect; a peer that connects
    /// and then says nothing is [`PeerError::Silent`].
    #[error("timed out waiting for {what}")]
    Timeout { what: String },
    /// The peer sent nothing at all for a full [`READ_TIMEOUT`]. The one
    /// failure that is genuinely silence — what a zcashd node in initial
    /// block download does with `getheaders`.
    #[error("the peer sent nothing for {secs}s while we waited for {what}")]
    Silent { what: String, secs: u64 },
    /// The peer kept talking but never sent what was asked for.
    #[error("the peer never sent {what}; it kept sending other messages")]
    Unanswered { what: String },
    /// More block data for one request than any honest reply holds.
    #[error("the peer sent over {mb} MB of block data for one request")]
    Oversized { mb: usize },
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
///
/// `Debug` reports the peer's address and height only. The socket itself is
/// not useful in a log line, and the address is what identifies which peer a
/// scan is talking to.
pub struct Peer {
    stream: TcpStream,
    network: P2pNetwork,
    /// The candidate string this peer was dialled as, so a caller can
    /// exclude exactly that candidate from a later pass.
    dialled_as: String,
    /// The peer's advertised chain height, from its `version`.
    pub peer_height: u32,
}

impl std::fmt::Debug for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Peer")
            .field(
                "addr",
                &self
                    .stream
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "<disconnected>".to_owned()),
            )
            .field("peer_height", &self.peer_height)
            .finish()
    }
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
            dialled_as: addr.to_owned(),
            peer_height: 0,
        };
        peer.handshake().await?;
        Ok(peer)
    }

    /// The address this peer was dialled as.
    pub fn dialled_as(&self) -> &str {
        &self.dialled_as
    }

    /// Close the connection now, rather than whenever this value is dropped.
    ///
    /// A caller replacing this peer must call it before dialling the
    /// replacement. Zebra keeps one inbound connection per IP and drops a
    /// second after the handshake, so a connection left open while the next
    /// is dialled makes the node already in use refuse its own replacement.
    ///
    /// Errors are ignored: a connection that cannot be shut down cleanly is
    /// one the peer has already given up on, which is the goal here.
    pub async fn close(&mut self) {
        let _ = self.stream.shutdown().await;
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
            .map_err(|_| PeerError::Silent {
                what: "a message header".to_owned(),
                secs: READ_TIMEOUT.as_secs(),
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
            .map_err(|_| PeerError::Silent {
                what: format!("the {} payload", header.command),
                secs: READ_TIMEOUT.as_secs(),
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
        Err(PeerError::Unanswered {
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

    /// Fetch full blocks, keyed by their own hash.
    ///
    /// Keyed rather than returned in order, because a peer may relay an
    /// unsolicited `block` at any time — normal propagation, not an attack.
    /// Pairing replies positionally with the request would then attribute
    /// one block's contents to another's slot, which for a scan is both
    /// catastrophic and invisible: every later commitment shifts and the
    /// witnesses prove a tree that never existed. The hash is recomputed
    /// from the bytes, so a peer cannot claim a block is one it is not.
    ///
    /// Requested in small batches. A single `getdata` naming a whole
    /// `getheaders` page is accepted and then simply not answered —
    /// measured against a real node, where one block returns instantly and
    /// 160 produce nothing before the read timeout. That failure is
    /// indistinguishable from a dead connection, so the cap lives here
    /// rather than waiting for a caller to hit it part-way through a scan
    /// of a million blocks.
    ///
    /// Even a small batch can be answered only in part (see
    /// [`PARTIAL_ANSWER_QUIET`]). When some blocks have arrived and the peer
    /// then goes quiet, the ones still missing are requested again. Each
    /// re-request must make progress: one that brings nothing for a full
    /// [`READ_TIMEOUT`] fails as before, so this cannot loop.
    pub async fn get_blocks(
        &mut self,
        hashes: &[[u8; 32]],
    ) -> Result<HashMap<[u8; 32], Vec<u8>>, PeerError> {
        let wanted: HashSet<[u8; 32]> = hashes.iter().copied().collect();
        let mut blocks: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(hashes.len());
        let mut held = 0usize;

        for chunk in hashes.chunks(GETDATA_BATCH) {
            // Track what this chunk still owes rather than reading a fixed
            // number of messages: counting an unsolicited block as a reply
            // would leave one we asked for unread and desynchronise the
            // stream for every later request.
            let mut missing: Vec<[u8; 32]> = chunk
                .iter()
                .filter(|h| !blocks.contains_key(*h))
                .copied()
                .collect();

            // One round per request. Every round but the first follows one
            // that made progress, so a chunk takes at most GETDATA_BATCH.
            while !missing.is_empty() {
                self.send("getdata", &encode_getdata_blocks(&missing))
                    .await?;
                let mut budget = missing.len() * 4 + 8;
                // Not-block messages, capped as `recv_until` caps them, so a
                // peer cannot keep a round alive with chatter alone.
                let mut chatter = 0usize;
                let mut progressed = false;

                while !missing.is_empty() {
                    // Once this request has been answered in part, a pause
                    // means the peer has stopped. Checked before every
                    // message, not only before each block: a node announces
                    // new blocks and transactions at any time, and one such
                    // message must not start a full read timeout. Peeking
                    // consumes nothing, so giving up on the wait cannot
                    // desynchronise the stream.
                    if progressed && !self.next_message_within(PARTIAL_ANSWER_QUIET).await {
                        break;
                    }
                    let (header, bytes) = self.recv().await?;
                    if header.command != "block" {
                        if header.command == "ping" {
                            self.send("pong", &bytes).await?;
                        }
                        chatter += 1;
                        if chatter > 256 {
                            return Err(PeerError::Unanswered {
                                what: "the blocks this peer was asked for".to_owned(),
                            });
                        }
                        continue;
                    }
                    if budget == 0 {
                        return Err(PeerError::Unanswered {
                            what: "the blocks this peer was asked for".to_owned(),
                        });
                    }
                    budget -= 1;

                    let Ok(hash) = super::block::block_hash(&bytes) else {
                        continue;
                    };
                    if !wanted.contains(&hash) {
                        continue; // unsolicited relay; not ours to use
                    }
                    held += bytes.len();
                    if bytes.len() > MAX_BLOCK_BYTES || held > MAX_BLOCKS_BYTES {
                        return Err(PeerError::Oversized {
                            mb: held / 1_000_000,
                        });
                    }
                    if blocks.insert(hash, bytes).is_none() {
                        if let Some(at) = missing.iter().position(|h| *h == hash) {
                            missing.remove(at);
                            progressed = true;
                        }
                    }
                }
            }
        }
        Ok(blocks)
    }

    /// Whether the peer starts another message within `wait`.
    ///
    /// True on EOF or a socket error too, so the read that follows reports
    /// them rather than this treating them as a pause.
    async fn next_message_within(&mut self, wait: Duration) -> bool {
        let mut byte = [0u8; 1];
        timeout(wait, self.stream.peek(&mut byte)).await.is_ok()
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

    /// The scan now runs through the 2022-23 spam era, whose blocks approach
    /// the consensus maximum. A full honest page must fit, or every page
    /// there fails and the scan rotates peers until it gives up.
    #[test]
    fn a_full_page_of_maximum_size_blocks_fits_the_byte_cap() {
        const { assert!(MAX_BLOCKS_BYTES >= MAX_PAGE_BLOCKS * MAX_BLOCK_BYTES) };
        const {
            assert!(
                MAX_PAGE_BLOCKS == 160,
                "what an honest `headers` reply holds"
            )
        };
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

    /// How a fake peer answers each `getdata`, by request number.
    #[derive(Clone, Copy)]
    enum Serve {
        /// Every block it names.
        All,
        /// Only the even-indexed entries, then silence — what Zebra does
        /// with a batch whose bodies add up to about a megabyte.
        EvenOnly,
        /// The even-indexed entries, then one unrelated `inv`, then
        /// silence. A live node announces new blocks and transactions at
        /// any time, including right after a partial answer.
        EvenThenInv,
        /// Nothing at all.
        Nothing,
    }

    /// A peer that handshakes, then answers `getdata` according to `plan`
    /// (the last entry repeats). Each request's hashes are recorded, in
    /// order, so a test can see what was asked for again.
    async fn partial_peer(
        blocks: Vec<Vec<u8>>,
        plan: Vec<Serve>,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<Vec<[u8; 32]>>>>) {
        use crate::p2p::wire::{encode_message, encode_version};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let by_hash: HashMap<[u8; 32], Vec<u8>> = blocks
            .into_iter()
            .map(|b| (super::super::block::block_hash(&b).unwrap(), b))
            .collect();
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = requests.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0u8; 24];
            while stream.read_exact(&mut header).await.is_ok() {
                let len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
                let mut payload = vec![0u8; len];
                if stream.read_exact(&mut payload).await.is_err() {
                    break;
                }
                if header[4..11] == *b"version" {
                    let version = encode_version(170_190, "/Zebra:7.0.0/", 10_000, 1, 0);
                    let mut out = encode_message(P2pNetwork::Regtest, "version", &version);
                    out.extend(encode_message(P2pNetwork::Regtest, "verack", &[]));
                    stream.write_all(&out).await.unwrap();
                } else if header[4..11] == *b"getdata" {
                    // One-byte count (tests stay under 253), then 36-byte
                    // inventory entries: type, hash.
                    let hashes: Vec<[u8; 32]> = payload[1..]
                        .chunks_exact(36)
                        .map(|inv| inv[4..].try_into().unwrap())
                        .collect();
                    let n = {
                        let mut seen = seen.lock().unwrap();
                        seen.push(hashes.clone());
                        seen.len() - 1
                    };
                    let serve = plan[n.min(plan.len() - 1)];
                    for (i, hash) in hashes.iter().enumerate() {
                        let send = match serve {
                            Serve::All => true,
                            Serve::EvenOnly | Serve::EvenThenInv => i % 2 == 0,
                            Serve::Nothing => false,
                        };
                        if send {
                            let msg = encode_message(P2pNetwork::Regtest, "block", &by_hash[hash]);
                            stream.write_all(&msg).await.unwrap();
                        }
                    }
                    if matches!(serve, Serve::EvenThenInv) {
                        // An empty inventory: one CompactSize zero.
                        let msg = encode_message(P2pNetwork::Regtest, "inv", &[0]);
                        stream.write_all(&msg).await.unwrap();
                    }
                }
            }
        });
        (addr, requests)
    }

    fn distinct_blocks(n: u8) -> (Vec<Vec<u8>>, Vec<[u8; 32]>) {
        use super::super::block::test_support::{legacy_test_transaction, test_block};
        let blocks: Vec<Vec<u8>> = (0..n)
            .map(|tag| test_block(&[legacy_test_transaction(tag)]))
            .collect();
        let hashes = blocks
            .iter()
            .map(|b| super::super::block::block_hash(b).unwrap())
            .collect();
        (blocks, hashes)
    }

    /// Measured against Zebra 7.0.0 at mainnet heights 9153..9168: one
    /// `getdata` for 16 blocks returned 11 within 0.3 s and then nothing,
    /// with no `notfound`. Waiting for the rest timed out, the caller
    /// treated the peer as dead, and the retry asked for the same batch
    /// forever. A partial answer followed by quiet must instead re-request
    /// just what is missing.
    #[tokio::test]
    async fn a_partially_answered_batch_is_re_requested_for_what_is_missing() {
        let (blocks, hashes) = distinct_blocks(20);
        let (addr, requests) = partial_peer(blocks, vec![Serve::EvenOnly, Serve::All]).await;
        let mut peer = Peer::connect(&addr, P2pNetwork::Regtest).await.unwrap();

        let got = peer.get_blocks(&hashes).await.expect("every block arrives");
        assert_eq!(got.len(), 20);
        for hash in &hashes {
            assert!(got.contains_key(hash));
        }

        // The re-request names only the blocks the first answer left out,
        // never the ones already held.
        let requests = requests.lock().unwrap();
        assert_eq!(requests[0], hashes[..GETDATA_BATCH]);
        let missing: Vec<[u8; 32]> = hashes[..GETDATA_BATCH]
            .iter()
            .skip(1)
            .step_by(2)
            .copied()
            .collect();
        assert_eq!(requests[1], missing);
    }

    /// Seen against Zebra on mainnet: the partial answer was followed by an
    /// unrelated message. The quiet window must cover every message, not
    /// just the wait for the next block, or that message starts a full
    /// read timeout and the peer is dropped as dead.
    #[tokio::test]
    async fn an_unrelated_message_after_a_partial_answer_does_not_stall_it() {
        let (blocks, hashes) = distinct_blocks(16);
        let (addr, requests) = partial_peer(blocks, vec![Serve::EvenThenInv, Serve::All]).await;
        let mut peer = Peer::connect(&addr, P2pNetwork::Regtest).await.unwrap();

        let got = peer.get_blocks(&hashes).await.expect("every block arrives");
        assert_eq!(got.len(), 16);
        assert_eq!(requests.lock().unwrap().len(), 2);
    }

    /// Re-requesting must not become a loop: a peer that answers part of a
    /// batch and then nothing ever again still fails, after one full
    /// read timeout with no progress.
    #[tokio::test]
    async fn a_peer_that_stops_answering_still_fails() {
        let (blocks, hashes) = distinct_blocks(16);
        let (addr, requests) = partial_peer(blocks, vec![Serve::EvenOnly, Serve::Nothing]).await;
        let mut peer = Peer::connect(&addr, P2pNetwork::Regtest).await.unwrap();

        let err = peer
            .get_blocks(&hashes)
            .await
            .expect_err("the peer went quiet");
        assert!(matches!(err, PeerError::Silent { .. }), "got {err:?}");
        assert_eq!(
            requests.lock().unwrap().len(),
            2,
            "one re-request, then give up"
        );
    }
}
