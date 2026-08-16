//! `FakeLightwalletd` — an in-process gRPC server speaking the lightwalletd
//! wire protocol, used by the C2 integration tests.
//!
//! Boots a tonic server on a loopback ephemeral port, answers `GetLightdInfo`
//! from a builder-supplied config, and (when given an upstream URL) forwards
//! every other RPC Argos uses to a real lightwalletd instance. The
//! `get_block_range` body honours the following builder knobs (compose
//! freely — multiple knobs can be active on the same fixture):
//!
//!   - `close_stream_after_blocks(N)` — after the first `N` compact blocks
//!     have been emitted on a stream, the fixture aborts the stream with a
//!     `tonic::Status` whose message contains the strings
//!     `run_wallet_sync_with_retry` matches against (`"h2 protocol error"`
//!     + `"GoAway"`). One-shot. Unblocks R-N8.
//!   - `inject_hostile_block_at_height(H)` — XOR all bytes of `prev_hash`
//!     at height `H` before forwarding. The block parses but breaks the
//!     chain-link invariant. One-shot. Unblocks R-N9.
//!   - `latency(Duration)` — sleep this long before each emitted block.
//!     Models a high-RTT link. Unblocks R-N13.
//!   - `bandwidth_bytes_per_sec(R)` — token-bucket per emitted block, so
//!     each `CompactBlock` of `n` bytes is followed by a `n / R` second
//!     sleep before the next is allowed. Models a bandwidth-constrained
//!     link. Unblocks R-N14.
//!   - `hang_after_blocks(N)` — emit `N` blocks normally, then the
//!     forwarder task parks itself indefinitely without sending or closing
//!     the stream. Models a dead peer (TCP up, no h2 frames). Drives R-N15.
//!
//! For R-N17 (captive-portal-shaped MitM), the fixture has nothing useful
//! to add — instead, see [`serve_captive_portal_shim`], a sibling helper
//! that binds a `TcpListener` and writes a raw `HTTP/1.1 200 OK` on each
//! accepted connection before closing. The shim does not speak gRPC at
//! all; the test points Argos at it and asserts an `Err`.
//!
//! Why proxy mode: it lets the bad-network tests reuse the real regtest
//! harness's compact-block stream for the happy-path prefix, then introduce
//! a fault at a chosen point. Synthesising a full chain in-process would be
//! an order-of-magnitude larger project.
//!
//! Gated entirely behind `cfg(feature = "argos-network")` — production builds
//! never see this file.

#![cfg(feature = "argos-network")]
#![allow(dead_code)] // Some helpers (e.g. the `latency` knob) await follow-up wiring.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use prost::Message as _;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Channel, Server};
use tonic::{Request, Response, Status};

// Re-export the generated proto code under a stable in-crate path. The
// `cash.z.wallet.sdk.rpc` package name produces an output file whose name
// contains dots; `include!` swallows that and exposes the contents inside
// this `pb` module.
#[rustfmt::skip]
#[allow(clippy::all, clippy::pedantic, missing_docs)]
mod pb {
    include!(concat!(env!("OUT_DIR"), "/cash.z.wallet.sdk.rpc.rs"));
}

use pb::compact_tx_streamer_server::{CompactTxStreamer, CompactTxStreamerServer};
use pb::{
    BlockId, BlockRange, ChainSpec, CompactBlock, Empty, GetAddressUtxosArg,
    GetAddressUtxosReply, GetAddressUtxosReplyList, GetSubtreeRootsArg, LightdInfo, RawTransaction,
    SendResponse,
    SubtreeRoot, TransparentAddressBlockFilter, TreeState, TxFilter,
};

// Argos's runtime client. The fixture uses the same generated client
// `zcash_client_backend::proto` ships to forward unknown RPCs upstream, so
// the wire format is guaranteed to match what Argos itself sends.
use zcash_client_backend::proto::service::compact_tx_streamer_client::CompactTxStreamerClient as UpstreamClient;

/// A running fake lightwalletd instance.
///
/// Listens on `127.0.0.1:NNNNN` (random ephemeral port). The server task is
/// owned by the `JoinHandle` in `_handle`; dropping the `FakeLightwalletd`
/// aborts the server task and frees the port.
pub struct FakeLightwalletd {
    /// Loopback URL the fixture is listening on, e.g. `http://127.0.0.1:NNNNN`.
    /// Pass this directly to `RecoveryService::start_scan`'s
    /// `lightwalletd_url`. Argos's `validate_lightwalletd_endpoint` accepts
    /// `http://127.0.0.1:...` because the host is loopback.
    pub url: String,
    /// JoinHandle for the tonic server task; dropping shuts the server down.
    _handle: tokio::task::JoinHandle<()>,
}

impl FakeLightwalletd {
    /// Begin building a new fixture. See [`FakeLightwalletdBuilder`].
    pub fn builder() -> FakeLightwalletdBuilder {
        FakeLightwalletdBuilder::default()
    }
}

/// Builder for [`FakeLightwalletd`].
///
/// Chain identity defaults are picked to satisfy `validate_lightwalletd_network`
/// when the operator selected `ZeckNetwork::Testnet` under the `argos-network`
/// feature: `chain_name = "regtest"`, `sapling_activation_height = 1` (the
/// Sapling-height check is skipped for the regtest chain name).
#[derive(Clone, Debug)]
pub struct FakeLightwalletdBuilder {
    /// `chain_name` returned by `GetLightdInfo`.
    chain_name: String,
    /// `sapling_activation_height` returned by `GetLightdInfo`.
    sapling_activation_height: u64,
    /// `block_height` returned by `GetLightdInfo` when no upstream is set.
    /// In proxy mode the upstream's value is forwarded instead.
    block_height: u64,
    /// If set, forward every RPC other than `GetLightdInfo` to this real
    /// lightwalletd. Must be a URL `tonic::transport::Channel::connect` accepts
    /// (e.g. `http://127.0.0.1:9067` for the regtest harness).
    upstream_url: Option<String>,
    // ─── Fault-injection knobs ──────────────────────────────────────────
    /// Inject a fixed delay before each emitted compact block on the
    /// `GetBlockRange` stream. Used by R-N13 to model a high-RTT link.
    latency: Option<Duration>,
    /// Abort the `GetBlockRange` stream after this many compact blocks have
    /// been emitted, surfacing a `Status` whose message matches the strings
    /// `run_wallet_sync_with_retry` retries on. Fires exactly once per
    /// fixture lifetime; subsequent calls forward cleanly. Unblocks R-N8.
    close_stream_after_blocks: Option<u64>,
    /// When the upstream returns the compact block at this height, mutate
    /// its `prev_hash` (XOR all bytes with 0xff) before forwarding. The
    /// resulting block parses but breaks the chain-link invariant, so
    /// `zcash_client_backend::sync` rejects it. Fires exactly once.
    /// Unblocks R-N9.
    inject_hostile_block_at_height: Option<u64>,
    /// Throttle bandwidth: after each block of `n` bytes, sleep for
    /// `n / rate` seconds before the next is permitted. Used by R-N14
    /// to model a bandwidth-constrained link. Composes with `latency` —
    /// the per-block delay is `latency + (bytes / rate)`.
    bandwidth_bytes_per_sec: Option<u32>,
    /// Emit this many blocks normally, then park the forwarder task forever
    /// without closing the stream. Models a dead peer (TCP up, no h2 frames).
    /// Used by R-N15.
    hang_after_blocks: Option<u64>,
}

impl Default for FakeLightwalletdBuilder {
    fn default() -> Self {
        Self {
            chain_name: "regtest".to_owned(),
            sapling_activation_height: 1,
            block_height: 0,
            upstream_url: None,
            latency: None,
            close_stream_after_blocks: None,
            inject_hostile_block_at_height: None,
            bandwidth_bytes_per_sec: None,
            hang_after_blocks: None,
        }
    }
}

impl FakeLightwalletdBuilder {
    /// Set the `chain_name` returned by `GetLightdInfo`. Defaults to
    /// `"regtest"`, which is what the `argos-network`-gated branch of
    /// `validate_lightwalletd_network` expects.
    pub fn chain_name(mut self, name: impl Into<String>) -> Self {
        self.chain_name = name.into();
        self
    }

    /// Override the Sapling activation height reported in `GetLightdInfo`.
    /// Defaults to 1 (regtest).
    pub fn sapling_activation_height(mut self, height: u64) -> Self {
        self.sapling_activation_height = height;
        self
    }

    /// Override the latest block height reported in `GetLightdInfo`. Ignored
    /// in proxy mode (the upstream's value is forwarded).
    pub fn block_height(mut self, height: u64) -> Self {
        self.block_height = height;
        self
    }

    /// Forward unknown RPCs to a real upstream lightwalletd. Required for
    /// every RPC except `GetLightdInfo` in this skeleton PR; the follow-up
    /// PR will add synthetic responders for the fault-injection cases that
    /// don't need a real backend.
    pub fn upstream(mut self, url: impl Into<String>) -> Self {
        self.upstream_url = Some(url.into());
        self
    }

    /// Sleep `latency` before each compact block on `GetBlockRange`. Models
    /// a high-RTT link. Composes with `bandwidth_bytes_per_sec`. Drives
    /// R-N13.
    pub fn latency(mut self, latency: Duration) -> Self {
        self.latency = Some(latency);
        self
    }

    /// Throttle outbound bandwidth on `GetBlockRange` to `rate` bytes per
    /// second using a per-block token-bucket sleep. Composes with
    /// `latency`. Drives R-N14.
    pub fn bandwidth_bytes_per_sec(mut self, rate: u32) -> Self {
        assert!(rate > 0, "bandwidth_bytes_per_sec must be > 0");
        self.bandwidth_bytes_per_sec = Some(rate);
        self
    }

    /// Emit `count` blocks normally on `GetBlockRange`, then park the
    /// forwarder forever without closing the stream. Models a dead peer
    /// (TCP up, no h2 frames). Drives R-N15.
    pub fn hang_after_blocks(mut self, count: u64) -> Self {
        self.hang_after_blocks = Some(count);
        self
    }

    /// After this many compact blocks have been emitted on a `GetBlockRange`
    /// stream, abort the stream with an error message
    /// `run_wallet_sync_with_retry` matches against (contains both
    /// `"h2 protocol error"` and `"GoAway"`). Fires exactly once per fixture
    /// lifetime; subsequent stream requests forward cleanly. Drives R-N8.
    pub fn close_stream_after_blocks(mut self, count: u64) -> Self {
        self.close_stream_after_blocks = Some(count);
        self
    }

    /// When the upstream returns the compact block at this height, mutate
    /// its `prev_hash` so the block parses but fails chain-link validation
    /// in `zcash_client_backend::sync`. Fires exactly once. Drives R-N9.
    pub fn inject_hostile_block_at_height(mut self, height: u64) -> Self {
        self.inject_hostile_block_at_height = Some(height);
        self
    }

    /// Bind a TCP listener on `127.0.0.1:0`, hand it to a tonic server, and
    /// return a `FakeLightwalletd` whose `url` points at the assigned port.
    pub async fn build(self) -> std::io::Result<FakeLightwalletd> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_addr: SocketAddr = listener.local_addr()?;
        let url = format!("http://{local_addr}");

        let service = FakeService::new(self).await;
        let server = CompactTxStreamerServer::new(service);

        let incoming = TcpListenerStream::new(listener);
        let handle = tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(server)
                .serve_with_incoming(incoming)
                .await;
        });

        Ok(FakeLightwalletd {
            url,
            _handle: handle,
        })
    }
}

/// Fault state shared across `get_block_range` invocations on the same
/// fixture. The `one_shot_triggered` flag governs the *one-shot* knobs
/// (close-stream, hostile-block, hang) — once they fire, subsequent stream
/// requests bypass them so the retry loop's next connection sees clean
/// behaviour. The *steady-state* knobs (latency, bandwidth) apply to every
/// stream unconditionally.
struct FaultState {
    // ─── One-shot knobs ────────────────────────────────────────────────
    close_stream_after_blocks: Option<u64>,
    inject_hostile_block_at_height: Option<u64>,
    hang_after_blocks: Option<u64>,
    one_shot_triggered: AtomicBool,
    // ─── Steady-state knobs ────────────────────────────────────────────
    latency: Option<Duration>,
    bandwidth_bytes_per_sec: Option<u32>,
}

impl FaultState {
    /// Whether the one-shot knobs are armed (set + not yet triggered). The
    /// steady-state knobs apply regardless.
    fn one_shot_armed(&self) -> bool {
        (self.close_stream_after_blocks.is_some()
            || self.inject_hostile_block_at_height.is_some()
            || self.hang_after_blocks.is_some())
            && !self.one_shot_triggered.load(Ordering::SeqCst)
    }

    /// Sleep for the per-block budget implied by `latency` + the
    /// bandwidth token-bucket cost of a `bytes`-sized block. Returns
    /// immediately when neither knob is set.
    async fn pace_per_block(&self, bytes: usize) {
        let bandwidth_delay = match self.bandwidth_bytes_per_sec {
            Some(rate) => Duration::from_secs_f64(bytes as f64 / f64::from(rate)),
            None => Duration::ZERO,
        };
        let total = self.latency.unwrap_or(Duration::ZERO) + bandwidth_delay;
        if !total.is_zero() {
            tokio::time::sleep(total).await;
        }
    }
}

/// Inner gRPC service implementing the (pruned) `CompactTxStreamer` trait.
struct FakeService {
    chain_name: String,
    sapling_activation_height: u64,
    block_height: u64,
    /// Lazily-connected upstream client. `None` means no proxy mode; every
    /// RPC other than `GetLightdInfo` returns `unimplemented`.
    upstream: Option<UpstreamClient<Channel>>,
    fault: Arc<FaultState>,
}

impl FakeService {
    async fn new(builder: FakeLightwalletdBuilder) -> Self {
        let upstream = match builder.upstream_url.as_deref() {
            Some(url) => {
                // We deliberately propagate connection errors through a
                // `panic` here rather than surfacing them: this only runs in
                // the test fixture, and a missing upstream is a test-setup
                // bug the developer wants to see loudly.
                let client = UpstreamClient::connect(url.to_owned())
                    .await
                    .unwrap_or_else(|err| {
                        panic!("FakeLightwalletd could not connect to upstream {url}: {err}")
                    });
                Some(client)
            }
            None => None,
        };

        Self {
            chain_name: builder.chain_name,
            sapling_activation_height: builder.sapling_activation_height,
            block_height: builder.block_height,
            upstream,
            fault: Arc::new(FaultState {
                close_stream_after_blocks: builder.close_stream_after_blocks,
                inject_hostile_block_at_height: builder.inject_hostile_block_at_height,
                hang_after_blocks: builder.hang_after_blocks,
                one_shot_triggered: AtomicBool::new(false),
                latency: builder.latency,
                bandwidth_bytes_per_sec: builder.bandwidth_bytes_per_sec,
            }),
        }
    }

    /// Return a fresh clone of the upstream client, or an `unavailable` Status
    /// when proxy mode is disabled. The clone is cheap — tonic channels share
    /// the underlying HTTP/2 connection.
    fn upstream(&self) -> Result<UpstreamClient<Channel>, Status> {
        self.upstream.clone().ok_or_else(|| {
            Status::unimplemented(
                "FakeLightwalletd: this RPC requires an upstream lightwalletd; \
                 call .upstream(url) on the builder",
            )
        })
    }
}

/// Translate between the *locally-generated* proto types (under `pb::`) and
/// the *upstream client's* proto types (under `zcash_client_backend::proto::*`).
/// The wire format is identical, so we go through `prost`'s
/// `Message::encode`/`decode`. This avoids leaking the upstream's type names
/// into the rest of the fixture and lets the proxy treat upstream/downstream
/// independently.
fn reencode<A, B>(from: &A) -> B
where
    A: prost::Message,
    B: prost::Message + Default,
{
    let mut buf = Vec::with_capacity(from.encoded_len());
    from.encode(&mut buf)
        .expect("prost::Message::encode into Vec cannot fail");
    B::decode(&buf[..])
        .expect("prost wire format is identical between locally- and upstream-generated types")
}

#[tonic::async_trait]
impl CompactTxStreamer for FakeService {
    /// Chain tip, as `zcash_client_backend::sync::run` asks for it.
    ///
    /// Proxied rather than synthesised: the sync loop uses this height to
    /// decide what range to request, so answering with anything other than
    /// the real upstream tip would make every fault-injection test scan a
    /// range that does not match the chain they were funded on.
    async fn get_latest_block(
        &self,
        request: Request<ChainSpec>,
    ) -> Result<Response<BlockId>, Status> {
        let mut upstream = self.upstream()?;
        let req = reencode::<_, zcash_client_backend::proto::service::ChainSpec>(request.get_ref());
        let resp = upstream.get_latest_block(req).await?.into_inner();
        Ok(Response::new(reencode::<_, BlockId>(&resp)))
    }

    type GetSubtreeRootsStream = ReceiverStream<Result<SubtreeRoot, Status>>;

    /// Shard-tree roots, also driven by `sync::run` rather than by Argos.
    ///
    /// Deliberately *not* subject to the fixture's latency, bandwidth, or
    /// one-shot fault injection. Those faults model a degraded connection
    /// during the block-download loop, which is what the resilience tests
    /// are about; corrupting tree initialisation instead would fail the scan
    /// before it starts, which is the very failure mode this RPC's absence
    /// used to cause.
    async fn get_subtree_roots(
        &self,
        request: Request<GetSubtreeRootsArg>,
    ) -> Result<Response<Self::GetSubtreeRootsStream>, Status> {
        let mut upstream = self.upstream()?;
        let req = reencode::<_, zcash_client_backend::proto::service::GetSubtreeRootsArg>(
            request.get_ref(),
        );
        let mut upstream_stream = upstream.get_subtree_roots(req).await?.into_inner();

        let (tx, rx) = mpsc::channel::<Result<SubtreeRoot, Status>>(16);
        tokio::spawn(async move {
            while let Some(item) = upstream_stream.message().await.transpose() {
                let mapped = match item {
                    Ok(root) => Ok(reencode::<_, SubtreeRoot>(&root)),
                    Err(status) => Err(Status::new(status.code(), status.message())),
                };
                if tx.send(mapped).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    type GetAddressUtxosStreamStream = ReceiverStream<Result<GetAddressUtxosReply, Status>>;

    /// Streaming transparent-output refresh, driven by `sync::run`.
    ///
    /// Distinct from `get_address_utxos` below despite the near-identical
    /// name: they are separate methods on the wire, and implementing only
    /// the unary one is what made this look present while it was missing.
    async fn get_address_utxos_stream(
        &self,
        request: Request<GetAddressUtxosArg>,
    ) -> Result<Response<Self::GetAddressUtxosStreamStream>, Status> {
        let mut upstream = self.upstream()?;
        let req = reencode::<_, zcash_client_backend::proto::service::GetAddressUtxosArg>(
            request.get_ref(),
        );
        let mut upstream_stream = upstream.get_address_utxos_stream(req).await?.into_inner();

        let (tx, rx) = mpsc::channel::<Result<GetAddressUtxosReply, Status>>(16);
        tokio::spawn(async move {
            while let Some(item) = upstream_stream.message().await.transpose() {
                let mapped = match item {
                    Ok(utxo) => Ok(reencode::<_, GetAddressUtxosReply>(&utxo)),
                    Err(status) => Err(Status::new(status.code(), status.message())),
                };
                if tx.send(mapped).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_lightd_info(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<LightdInfo>, Status> {
        // In proxy mode we still synthesise the response so the fixture can
        // claim its own chain identity (the upstream may legitimately be a
        // testnet or mainnet server; the fixture should still look like a
        // regtest to Argos under argos-network).
        let block_height = if let Some(mut upstream) = self.upstream.clone() {
            // Best-effort: ask the upstream for its tip height so the proxy
            // mode reports a realistic value, but fall back to the configured
            // value if the upstream call fails.
            match upstream
                .get_lightd_info(zcash_client_backend::proto::service::Empty {})
                .await
            {
                Ok(info) => info.into_inner().block_height,
                Err(_) => self.block_height,
            }
        } else {
            self.block_height
        };

        Ok(Response::new(LightdInfo {
            vendor: "argos-fake-lightwalletd".to_owned(),
            chain_name: self.chain_name.clone(),
            sapling_activation_height: self.sapling_activation_height,
            block_height,
            ..LightdInfo::default()
        }))
    }

    async fn get_block(&self, request: Request<BlockId>) -> Result<Response<CompactBlock>, Status> {
        let mut upstream = self.upstream()?;
        let req = reencode::<_, zcash_client_backend::proto::service::BlockId>(request.get_ref());
        let resp = upstream.get_block(req).await?.into_inner();
        Ok(Response::new(reencode::<_, CompactBlock>(&resp)))
    }

    type GetBlockRangeStream = ReceiverStream<Result<CompactBlock, Status>>;

    async fn get_block_range(
        &self,
        request: Request<BlockRange>,
    ) -> Result<Response<Self::GetBlockRangeStream>, Status> {
        let mut upstream = self.upstream()?;
        let req =
            reencode::<_, zcash_client_backend::proto::service::BlockRange>(request.get_ref());
        let mut upstream_stream = upstream.get_block_range(req).await?.into_inner();

        let (tx, rx) = mpsc::channel::<Result<CompactBlock, Status>>(16);
        let fault = self.fault.clone();
        tokio::spawn(async move {
            // Capture the one-shot armed state + thresholds up front so
            // subsequent stream requests (which happen during retry) see
            // clean behaviour without racing against another forwarder.
            let one_shot_active = fault.one_shot_armed();
            let close_after = fault.close_stream_after_blocks;
            let hostile_height = fault.inject_hostile_block_at_height;
            let hang_after = fault.hang_after_blocks;

            let mut emitted: u64 = 0;
            while let Some(item) = upstream_stream.message().await.transpose() {
                // Steady-state pacing: every successful block is paced by
                // latency + bandwidth before it leaves the fixture.
                let block_bytes = item.as_ref().ok().map(|b| b.encoded_len()).unwrap_or(0);
                fault.pace_per_block(block_bytes).await;

                let mapped = match item {
                    Ok(block) => {
                        // R-N9: mutate the compact block at the target height.
                        let mut local = reencode::<_, CompactBlock>(&block);
                        if one_shot_active && hostile_height == Some(local.height) {
                            if local.prev_hash.is_empty() {
                                local.prev_hash = vec![0xff; 32];
                            } else {
                                for b in local.prev_hash.iter_mut() {
                                    *b ^= 0xff;
                                }
                            }
                            fault.one_shot_triggered.store(true, Ordering::SeqCst);
                        }
                        Ok(local)
                    }
                    Err(status) => Err(Status::new(status.code(), status.message())),
                };

                let is_block = mapped.is_ok();
                if tx.send(mapped).await.is_err() {
                    // Client disconnected — nothing more to do.
                    break;
                }
                if is_block {
                    emitted += 1;
                }

                // R-N8: after N blocks have flowed through, abort the stream
                // with a Status whose message matches the production retry
                // matcher in `run_wallet_sync_with_retry`.
                if one_shot_active
                    && close_after == Some(emitted)
                    && !fault.one_shot_triggered.load(Ordering::SeqCst)
                {
                    fault.one_shot_triggered.store(true, Ordering::SeqCst);
                    let _ = tx
                        .send(Err(Status::unavailable(
                            "h2 protocol error: GoAway (simulated by FakeLightwalletd)",
                        )))
                        .await;
                    break;
                }

                // R-N15: after N blocks, park the forwarder forever without
                // closing the stream. The client awaits on an unending channel;
                // the test's outer `tokio::time::timeout` is the only thing
                // that distinguishes "Argos has a watchdog and surfaced Err"
                // from "Argos hung indefinitely". The mpsc Sender stays alive
                // here so the receiver doesn't observe stream-end.
                if one_shot_active
                    && hang_after == Some(emitted)
                    && !fault.one_shot_triggered.load(Ordering::SeqCst)
                {
                    fault.one_shot_triggered.store(true, Ordering::SeqCst);
                    let _hold_sender_alive = tx;
                    std::future::pending::<()>().await;
                    unreachable!("pending() never resolves");
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_transaction(
        &self,
        request: Request<TxFilter>,
    ) -> Result<Response<RawTransaction>, Status> {
        let mut upstream = self.upstream()?;
        let req = reencode::<_, zcash_client_backend::proto::service::TxFilter>(request.get_ref());
        let resp = upstream.get_transaction(req).await?.into_inner();
        Ok(Response::new(reencode::<_, RawTransaction>(&resp)))
    }

    async fn send_transaction(
        &self,
        request: Request<RawTransaction>,
    ) -> Result<Response<SendResponse>, Status> {
        let mut upstream = self.upstream()?;
        let req =
            reencode::<_, zcash_client_backend::proto::service::RawTransaction>(request.get_ref());
        let resp = upstream.send_transaction(req).await?.into_inner();
        Ok(Response::new(reencode::<_, SendResponse>(&resp)))
    }

    type GetTaddressTxidsStream = ReceiverStream<Result<RawTransaction, Status>>;

    async fn get_taddress_txids(
        &self,
        request: Request<TransparentAddressBlockFilter>,
    ) -> Result<Response<Self::GetTaddressTxidsStream>, Status> {
        let mut upstream = self.upstream()?;
        let req = reencode::<_, zcash_client_backend::proto::service::TransparentAddressBlockFilter>(
            request.get_ref(),
        );
        let mut upstream_stream = upstream.get_taddress_txids(req).await?.into_inner();

        let (tx, rx) = mpsc::channel::<Result<RawTransaction, Status>>(16);
        tokio::spawn(async move {
            while let Some(item) = upstream_stream.message().await.transpose() {
                let mapped = match item {
                    Ok(raw) => Ok(reencode::<_, RawTransaction>(&raw)),
                    Err(status) => Err(Status::new(status.code(), status.message())),
                };
                if tx.send(mapped).await.is_err() {
                    break;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_tree_state(
        &self,
        request: Request<BlockId>,
    ) -> Result<Response<TreeState>, Status> {
        let mut upstream = self.upstream()?;
        let req = reencode::<_, zcash_client_backend::proto::service::BlockId>(request.get_ref());
        let resp = upstream.get_tree_state(req).await?.into_inner();
        Ok(Response::new(reencode::<_, TreeState>(&resp)))
    }

    async fn get_address_utxos(
        &self,
        request: Request<GetAddressUtxosArg>,
    ) -> Result<Response<GetAddressUtxosReplyList>, Status> {
        let mut upstream = self.upstream()?;
        let req = reencode::<_, zcash_client_backend::proto::service::GetAddressUtxosArg>(
            request.get_ref(),
        );
        let resp = upstream.get_address_utxos(req).await?.into_inner();
        Ok(Response::new(reencode::<_, GetAddressUtxosReplyList>(
            &resp,
        )))
    }
}

// ─── Captive-portal MitM shim (R-N17) ───────────────────────────────────────
//
// A separate tiny helper that has nothing to do with the gRPC fixture above.
// Binds a `TcpListener` on a random loopback port, and on every accepted
// connection writes a plain `HTTP/1.1 200 OK` response (Content-Length: 0)
// and closes. This is what a captive portal typically looks like at the
// byte level — the user's "lightwalletd endpoint" accepts the TCP connect,
// completes a write, and never says anything h2-shaped.
//
// Argos's TLS-then-gRPC stack must surface this as Err rather than silently
// treating it as a successful empty response. The test points Argos at the
// shim's URL and asserts an error within a bounded time.

/// Handle to a running captive-portal shim. Drop to free the port.
pub struct CaptivePortalShim {
    /// Loopback URL the shim is listening on (`http://127.0.0.1:N`).
    pub url: String,
    _handle: tokio::task::JoinHandle<()>,
}

/// Spin up a captive-portal-shaped MitM on a random loopback port. Returns
/// a [`CaptivePortalShim`]; dropping it aborts the listener task and frees
/// the port.
pub async fn serve_captive_portal_shim() -> std::io::Result<CaptivePortalShim> {
    use tokio::io::AsyncWriteExt;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_addr: SocketAddr = listener.local_addr()?;
    let url = format!("http://{local_addr}");

    let handle = tokio::spawn(async move {
        // Loop accepting connections forever. Each gets an HTTP 200 + close.
        // Any error from accept() (e.g. listener dropped) terminates the task.
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                // Best-effort: a write error here means the client already
                // closed, which is fine for a captive-portal simulator.
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });

    Ok(CaptivePortalShim {
        url,
        _handle: handle,
    })
}
