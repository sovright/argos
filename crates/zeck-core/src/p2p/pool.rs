//! Finding a peer that will actually talk to us.
//!
//! # Why this is not just `connect()` in a loop
//!
//! Most nodes advertised by the DNS seeds refuse inbound connections. They
//! accept the TCP handshake and close immediately, before any protocol
//! exchange — measured against the mainnet seeds, better than nine in ten
//! behave this way, and an identical close happens whether or not a
//! `version` message is sent. That is a connection-slot refusal, not a
//! rejection of anything we send.
//!
//! The consequence is that a sequential walk over the seed list looks
//! exactly like a broken client: every attempt fails, in order, slowly. The
//! fix is to try many candidates at once and take whoever answers first,
//! then use that peer to learn about others.
//!
//! # Diagnosis matters here
//!
//! When no peer can be reached, the reason must be distinguishable. "Every
//! peer refused a connection slot" and "this machine has no working DNS" and
//! "something is rewriting our traffic" all present as *no peers*, but only
//! the first is normal and worth retrying. A recovery tool that collapses
//! them into "connection failed" sends people chasing their firewall when
//! the network was merely busy.
//!
//! The reverse mistake is just as costly, and this module once made it: a
//! timeout was counted as a refusal, so a network that drops outbound 8233
//! was told the peers were busy and to retry. Refusal, silence, and
//! everything else are therefore three separate counts ([`FailureTally`]),
//! and the advice in [`PoolError::AllPeersRefused`] follows from which one
//! dominates.

use std::collections::BTreeSet;
use std::time::Duration;

use super::{
    peer::{Peer, PeerError},
    wire::P2pNetwork,
};

/// DNS seeds, as used by zcashd and zebrad.
const MAINNET_SEEDS: &[&str] = &[
    "mainnet.seeder.zfnd.org:8233",
    "dnsseed.z.cash:8233",
    "dnsseed.str4d.xyz:8233",
];

/// Public Zcash nodes operated by Sovright, tried after the DNS seeds.
///
/// # Why these exist
///
/// Measured against the mainnet DNS seeds, 38 of 38 peers refused a
/// connection slot — that is the normal state of the public network, not an
/// outage. A recovery tool that depends on catching a free slot works for
/// operators and fails for everyone else, which inverts who it is for.
///
/// Tried *after* the DNS seeds, never instead of them: a user who can reach
/// the open network should, and Argos should not quietly centralise onto one
/// operator's infrastructure. These are the fallback for when the public
/// network will not answer.
///
/// Trusting them is not required. Every header is checked for proof of work
/// and the chain is pinned to known block hashes, so a seed peer cannot feed
/// a fabricated history — it can only decline to serve. What these nodes see
/// is which blocks a user requests, which is the ordinary privacy cost of
/// any light-client-shaped query and is why they are not tried first.
const SOVRIGHT_MAINNET_NODES: &[&str] = &[
    "136.115.98.175:8233",
    "34.80.219.125:8233",
    "34.182.139.187:8233",
    "34.91.248.94:8233",
];

const TESTNET_SEEDS: &[&str] = &[
    "testnet.seeder.zfnd.org:18233",
    "dnsseed.testnet.z.cash:18233",
];

/// How many connections to race at once.
///
/// Sized against the observed refusal rate rather than picked round: with
/// roughly one usable peer in ten, a batch of this size finds one on the
/// first round most of the time, while staying polite enough that we are not
/// hammering the network.
const CONCURRENT_ATTEMPTS: usize = 12;

/// How long a peer remembers us after an inbound connection.
///
/// Zebra accepts one inbound connection per source IP per
/// `MIN_PEER_RECONNECTION_DELAY` (59+20+20+20 seconds) and silently drops
/// anything sooner — before the handshake, with no message. Reconnecting to
/// the same peer inside this window is therefore guaranteed to fail, and
/// fails identically to every other refusal, so a retry loop that ignores it
/// looks exactly like a broken client.
///
/// Consequences, both load-bearing for a scan that runs for hours:
/// a dropped connection should be replaced by a *different* peer rather than
/// retried, and the connection that is working must be kept alive rather
/// than reopened per request.
/// Public because a long-running scan needs it: on losing its peer it must
/// either move to a different one or wait this long, and there is no way to
/// discover that from the failure itself.
pub const PEER_RECONNECT_DELAY: Duration = Duration::from_secs(119);

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// Every candidate was tried and none completed a handshake.
    ///
    /// The name is historical: it covers silence and other faults as well as
    /// refusals, and the counts say which. `fallback_refused` is how many of
    /// the refusals came from [`SOVRIGHT_MAINNET_NODES`].
    #[error("{}", describe_no_peer(*tried, *refused, *timed_out, *other, *fallback_refused))]
    AllPeersRefused {
        tried: usize,
        refused: usize,
        timed_out: usize,
        other: usize,
        fallback_refused: usize,
    },
    #[error(
        "could not resolve any Zcash DNS seed ({0}). This usually means no internet \
         connection, or DNS is blocked on this network."
    )]
    NoSeedsResolved(String),
}

/// The text of [`PoolError::AllPeersRefused`].
///
/// This is the only thing a stuck user sees, and what they do next depends
/// on it, so each branch gives advice that is true for that case rather than
/// one sentence stretched over all of them:
///
/// - Mostly silence. A full peer closes the connection; it does not ignore
///   it. Silence from most of the network points at something between this
///   machine and the peers dropping the traffic, and retrying from the same
///   network cannot fix that. "Most" rather than "any", because a handful of
///   slow or dead addresses among the seeds is ordinary.
/// - Refusals that include the Sovright fallback nodes. "Retrying usually
///   succeeds" was only ever true because the fallback had room. A user was
///   told it for two days while all four fallback nodes were full; once they
///   have refused as well, the honest advice is to wait or to bring a node.
/// - Refusals alone. The routine case, and the only one where an immediate
///   retry is good advice.
/// - No refusals at all. Whatever happened, it is not a busy network.
fn describe_no_peer(
    tried: usize,
    refused: usize,
    timed_out: usize,
    other: usize,
    fallback_refused: usize,
) -> String {
    const OWN_NODE: &str = "supply a node you know is reachable with --peer host:port on \
                            `argos scan-sprout`";

    if tried == 0 {
        return format!("there were no Zcash peer addresses to try. To continue, {OWN_NODE}.");
    }

    let head = "no Zcash peer would accept a connection.";
    if timed_out * 2 > tried {
        format!(
            "{head} {timed_out} of {tried} peers never answered at all ({refused} refused a \
             connection slot, {other} failed for other reasons). A busy peer refuses \
             quickly; silence from most of them usually means outbound connections to port \
             8233 (18233 on testnet) are blocked on this network by a firewall, VPN, or \
             restrictive Wi-Fi. Retrying from the same network is unlikely to help. Try a \
             different network, or {OWN_NODE}."
        )
    } else if fallback_refused > 0 {
        format!(
            "{head} {refused} of {tried} peers refused a connection slot, including \
             {fallback_refused} of the Sovright fallback nodes that exist for when the \
             public network is full ({timed_out} timed out, {other} failed for other \
             reasons). The fallback nodes are also at capacity, so retrying straight away \
             is unlikely to succeed. Try again later, or {OWN_NODE}."
        )
    } else if refused == 0 {
        format!(
            "{head} None of the {tried} peers tried refused a connection slot, so this is \
             not the network being busy: {timed_out} timed out and {other} failed for other \
             reasons. Check this machine's internet connection, or {OWN_NODE}."
        )
    } else {
        format!(
            "{head} {refused} of {tried} peers refused a connection slot, which is normal \
             when the network is busy — retrying usually succeeds. ({timed_out} timed out, \
             {other} failed for other reasons.)"
        )
    }
}

/// Resolve the DNS seeds into candidate peer addresses.
pub async fn resolve_seeds(network: P2pNetwork) -> Result<Vec<String>, PoolError> {
    let seeds = match network {
        P2pNetwork::Mainnet => MAINNET_SEEDS,
        P2pNetwork::Testnet => TESTNET_SEEDS,
        // Regtest has no seeds; callers pass an address directly.
        P2pNetwork::Regtest => &[],
    };

    // A set, because the seeds overlap heavily and a duplicate address is a
    // wasted connection slot in the race below.
    let mut addrs = BTreeSet::new();
    let mut errors = Vec::new();
    for seed in seeds {
        match tokio::net::lookup_host(*seed).await {
            Ok(resolved) => addrs.extend(resolved.map(|a| a.to_string())),
            Err(err) => errors.push(format!("{seed}: {err}")),
        }
    }

    let mut resolved: Vec<String> = addrs.into_iter().collect();

    // Appended, so they are only reached once the DNS-seeded peers have
    // been tried and refused.
    //
    // Skipping any the seeders already advertise. Now that these nodes are
    // publicly reachable the DNS seeders have started returning them, and
    // appending a second copy would spend two connection slots on one host
    // in a batch sized for distinct peers.
    if matches!(network, P2pNetwork::Mainnet) {
        for node in SOVRIGHT_MAINNET_NODES {
            if !resolved.iter().any(|s| s == node) {
                resolved.push((*node).to_owned());
            }
        }
    }

    if resolved.is_empty() {
        return Err(PoolError::NoSeedsResolved(if errors.is_empty() {
            "the seeds resolved to no addresses".to_owned()
        } else {
            errors.join("; ")
        }));
    }
    Ok(resolved)
}

/// Race a batch of candidates and return the first peer that completes a
/// handshake.
///
/// Losing attempts are cancelled as soon as one wins, so a peer that would
/// have taken the full timeout does not hold up the scan.
async fn race_batch(candidates: &[String], network: P2pNetwork) -> (Option<Peer>, FailureTally) {
    let mut set = tokio::task::JoinSet::new();
    for addr in candidates {
        let addr = addr.clone();
        // The address travels with the result: which peer failed matters as
        // much as how, because a refusal from a fallback node changes what
        // the user should be told.
        set.spawn(async move {
            let result = Peer::connect(&addr, network).await;
            (addr, result)
        });
    }

    let mut tally = FailureTally::default();
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok((_, Ok(peer))) => {
                // Dropping the set aborts the rest.
                return (Some(peer), tally);
            }
            Ok((addr, Err(err))) => tally.record(&addr, &err),
            Err(_) => tally.other += 1,
        }
    }
    (None, tally)
}

/// Why the candidates that failed, failed.
///
/// Three buckets rather than two, because the three call for different
/// advice: a refusal is routine, silence suggests a blocked port, and
/// anything else is a fault worth reading. Every failure lands in exactly
/// one of `refused`, `timed_out` and `other`, so on a total failure they sum
/// to the number tried.
///
/// `fallback_refused` is not a fourth bucket but a subset of `refused`: the
/// refusals that came from [`SOVRIGHT_MAINNET_NODES`]. It is tracked because
/// the promise that retrying works rests on those nodes having room.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FailureTally {
    refused: usize,
    timed_out: usize,
    other: usize,
    fallback_refused: usize,
}

impl FailureTally {
    fn record(&mut self, addr: &str, err: &PeerError) {
        if is_slot_refusal(err) {
            self.refused += 1;
            // Only a refusal counts here. A fallback node that stayed silent
            // is evidence about the path to it, not about its capacity.
            if SOVRIGHT_MAINNET_NODES.contains(&addr) {
                self.fallback_refused += 1;
            }
        } else if is_timeout(err) {
            self.timed_out += 1;
        } else {
            self.other += 1;
        }
    }

    fn absorb(&mut self, batch: FailureTally) {
        self.refused += batch.refused;
        self.timed_out += batch.timed_out;
        self.other += batch.other;
        self.fallback_refused += batch.fallback_refused;
    }

    fn into_error(self, tried: usize) -> PoolError {
        PoolError::AllPeersRefused {
            tried,
            refused: self.refused,
            timed_out: self.timed_out,
            other: self.other,
            fallback_refused: self.fallback_refused,
        }
    }
}

/// A pool failure means no peer was reached, and nothing else.
///
/// It was once mapped to `ZeckError::Broadcast` at the call site, so a scan
/// that had not connected — let alone sent a transaction — reported
/// "broadcast failed". The conversion lives here so there is one mapping and
/// no call site can pick a different label.
impl From<PoolError> for crate::error::ZeckError {
    fn from(err: PoolError) -> Self {
        Self::PeerConnection(err.to_string())
    }
}

/// Whether an error is a peer declining to give us a connection slot, as
/// opposed to something wrong on our side.
///
/// Both present as a failed connection, but only this kind is routine and
/// worth retrying, so they are counted separately and reported separately.
///
/// A timeout is deliberately *not* a refusal. A peer with no free slot
/// answers — it completes the TCP handshake and closes, or resets — whereas
/// a timeout is no answer at all, which is also exactly what a firewall
/// dropping outbound 8233 produces. See [`is_timeout`].
fn is_slot_refusal(err: &PeerError) -> bool {
    match err {
        PeerError::Closed => true,
        PeerError::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionAborted
        ),
        PeerError::Connect { source, .. } => source.kind() == std::io::ErrorKind::ConnectionRefused,
        _ => false,
    }
}

/// Whether an error is a peer never answering, at any stage.
///
/// Covers our own handshake deadline and the operating system's connect
/// timeout alike: from the user's side both are silence, and silence from
/// most of the network is the signature of a blocked port rather than a busy
/// one.
fn is_timeout(err: &PeerError) -> bool {
    match err {
        PeerError::Timeout { .. } => true,
        PeerError::Io(io) | PeerError::Connect { source: io, .. } => {
            io.kind() == std::io::ErrorKind::TimedOut
        }
        _ => false,
    }
}

/// Connect to any usable peer on `network`, trying candidates in batches.
///
/// `extra` is tried first, so a caller with a known-good node (or a regtest
/// instance) never depends on the seeds at all.
pub async fn connect_to_any(
    network: P2pNetwork,
    extra: &[String],
    max_rounds: usize,
) -> Result<Peer, PoolError> {
    let mut candidates: Vec<String> = extra.to_vec();
    if !matches!(network, P2pNetwork::Regtest) {
        candidates.extend(resolve_seeds(network).await?);
    }

    let mut tried = 0;
    let mut tally = FailureTally::default();

    // Each round takes a *fresh* slice of candidates rather than retrying the
    // ones that just refused: a peer that refused seconds ago will refuse for
    // the next two minutes regardless of why, so re-dialling it wastes the
    // round.
    for round in 0..max_rounds.max(1) {
        let start = round * CONCURRENT_ATTEMPTS;
        let Some(batch) = candidates.get(start..) else {
            break;
        };
        if batch.is_empty() {
            break;
        }
        let batch = &batch[..batch.len().min(CONCURRENT_ATTEMPTS)];
        tried += batch.len();

        let (peer, failures) = race_batch(batch, network).await;
        tally.absorb(failures);
        if let Some(peer) = peer {
            return Ok(peer);
        }

        // A short pause between rounds: the refusals are capacity-driven, so
        // immediately retrying the same hosts is both rude and pointless.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Err(tally.into_error(tried))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distinction the error message depends on. A peer declining a slot
    /// is routine; a checksum failure means something is rewriting our
    /// traffic, and telling a user to "just retry" would be wrong.
    ///
    /// Silence is a third thing and must not be folded into either. An
    /// earlier version counted a timeout as a refusal, so a network that
    /// drops outbound 8233 produced "N of N peers refused ... retrying
    /// usually succeeds" — the exact misdiagnosis the module doc rules out.
    #[test]
    fn slot_refusals_are_told_apart_from_real_faults() {
        assert!(is_slot_refusal(&PeerError::Closed));
        assert!(is_slot_refusal(&PeerError::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        ))));
        assert!(is_slot_refusal(&connect_error(
            std::io::ErrorKind::ConnectionRefused
        )));

        assert!(!is_slot_refusal(&PeerError::Timeout {
            what: "a header".to_owned()
        }));
        assert!(!is_slot_refusal(&connect_error(
            std::io::ErrorKind::TimedOut
        )));

        assert!(!is_slot_refusal(&PeerError::Wire(
            super::super::wire::WireError::BadChecksum
        )));
        assert!(!is_slot_refusal(&PeerError::ProtocolTooOld(170_002)));
    }

    fn connect_error(kind: std::io::ErrorKind) -> PeerError {
        PeerError::Connect {
            addr: "203.0.113.1:8233".to_owned(),
            source: std::io::Error::from(kind),
        }
    }

    /// A peer that never answers is not a peer that said no. Both the
    /// handshake timeout and the operating system's own connect timeout are
    /// silence, wherever in the exchange they happen.
    #[test]
    fn silence_is_recognised_as_a_timeout() {
        assert!(is_timeout(&PeerError::Timeout {
            what: "a version".to_owned()
        }));
        assert!(is_timeout(&connect_error(std::io::ErrorKind::TimedOut)));
        assert!(is_timeout(&PeerError::Io(std::io::Error::from(
            std::io::ErrorKind::TimedOut
        ))));

        assert!(!is_timeout(&PeerError::Closed));
        assert!(!is_timeout(&connect_error(
            std::io::ErrorKind::ConnectionRefused
        )));
    }

    /// The tally is what the message is built from, so each failure has to
    /// land in exactly one bucket, and a refusal from a Sovright node has to
    /// be remembered as such.
    #[test]
    fn each_failure_lands_in_exactly_one_bucket() {
        let mut tally = FailureTally::default();
        tally.record("203.0.113.1:8233", &PeerError::Closed);
        tally.record(
            "203.0.113.2:8233",
            &PeerError::Timeout {
                what: "a version".to_owned(),
            },
        );
        tally.record("203.0.113.3:8233", &PeerError::ProtocolTooOld(170_002));
        tally.record(SOVRIGHT_MAINNET_NODES[0], &PeerError::Closed);
        // A fallback node that stayed silent did not refuse, and must not be
        // reported as being at capacity.
        tally.record(
            SOVRIGHT_MAINNET_NODES[1],
            &PeerError::Timeout {
                what: "a version".to_owned(),
            },
        );

        assert_eq!(
            tally,
            FailureTally {
                refused: 2,
                timed_out: 2,
                other: 1,
                fallback_refused: 1,
            }
        );
    }

    fn all_failed(tried: usize, tally: FailureTally) -> String {
        tally.into_error(tried).to_string()
    }

    /// The failure message is the only thing a stuck user sees, so it has to
    /// say what happened and whether retrying is worth it.
    #[test]
    fn the_all_refused_error_explains_itself() {
        let err = all_failed(
            38,
            FailureTally {
                refused: 33,
                timed_out: 2,
                other: 3,
                fallback_refused: 0,
            },
        );
        assert!(err.contains("38"));
        assert!(err.contains("33"));
        assert!(err.contains("2 timed out"), "timeouts are reported: {err}");
        assert!(
            err.contains("retrying usually succeeds"),
            "a capacity refusal is routine and the user should be told to retry"
        );
        assert!(
            !err.contains("blocked"),
            "a couple of slow peers is not evidence of a blocked port: {err}"
        );
    }

    /// A network that drops outbound 8233 fails every attempt by timeout.
    /// Telling that user the network is busy and to retry sends them round
    /// in circles; nothing will change until they change network.
    #[test]
    fn a_blocked_port_is_not_reported_as_a_busy_network() {
        let err = all_failed(
            34,
            FailureTally {
                refused: 0,
                timed_out: 34,
                other: 0,
                fallback_refused: 0,
            },
        );
        assert!(err.contains("34 of 34"), "{err}");
        assert!(err.contains("8233"), "{err}");
        assert!(err.contains("blocked"), "{err}");
        assert!(!err.contains("retrying usually succeeds"), "{err}");
        assert!(!err.contains("34 of 34 peers refused"), "{err}");

        // Mostly silence, with a stray refusal, is still the blocked-port
        // picture rather than the busy-network one.
        let mostly = all_failed(
            34,
            FailureTally {
                refused: 3,
                timed_out: 30,
                other: 1,
                fallback_refused: 0,
            },
        );
        assert!(mostly.contains("blocked"), "{mostly}");
        assert!(!mostly.contains("retrying usually succeeds"), "{mostly}");
    }

    /// The report this was written for: 34 of 34 refused, the four Sovright
    /// nodes among them, for two days. "Retrying usually succeeds" rests on
    /// the fallback having room; once it has refused too, the promise is
    /// false and the user needs a route that does not depend on luck.
    #[test]
    fn the_retry_promise_is_withdrawn_when_the_fallback_also_refused() {
        let err = all_failed(
            34,
            FailureTally {
                refused: 34,
                timed_out: 0,
                other: 0,
                fallback_refused: 4,
            },
        );
        assert!(err.contains("34 of 34"), "{err}");
        assert!(!err.contains("retrying usually succeeds"), "{err}");
        assert!(err.contains("fallback"), "{err}");
        assert!(err.contains("at capacity"), "{err}");
        assert!(
            err.contains("--peer host:port"),
            "the way out has to be named: {err}"
        );
    }

    /// Retrying is only routine advice for refusals. If nothing refused,
    /// whatever went wrong is not the busy-network case.
    #[test]
    fn retrying_is_not_promised_when_nothing_refused() {
        let err = all_failed(
            12,
            FailureTally {
                refused: 0,
                timed_out: 2,
                other: 10,
                fallback_refused: 0,
            },
        );
        assert!(!err.contains("retrying usually succeeds"), "{err}");
    }

    /// A scan that never reached a peer has not broadcast anything. It was
    /// once reported as "broadcast failed", which sent a user looking for a
    /// transaction that did not exist.
    #[test]
    fn a_failed_connection_is_not_called_a_broadcast_failure() {
        let err = crate::error::ZeckError::from(FailureTally::default().into_error(0));
        assert!(
            matches!(err, crate::error::ZeckError::PeerConnection(_)),
            "got {err:?}"
        );
        let text = err.to_string();
        assert!(!text.contains("broadcast"), "{text}");
        assert!(
            text.starts_with("could not reach the Zcash network"),
            "{text}"
        );
    }

    /// The reconnect delay must match Zebra's, or a scan that loses its
    /// connection retries into a guaranteed refusal and looks broken.
    #[test]
    fn the_reconnect_delay_matches_zebras_window() {
        // MIN_PEER_RECONNECTION_DELAY = 59 + 20 + 20 + 20 seconds.
        assert_eq!(PEER_RECONNECT_DELAY.as_secs(), 119);
    }

    #[test]
    fn a_dns_failure_is_not_reported_as_peers_refusing() {
        let err = PoolError::NoSeedsResolved("dns down".to_owned()).to_string();
        assert!(err.contains("DNS"));
        assert!(
            !err.contains("refused"),
            "a resolution failure must not be blamed on peers"
        );
    }

    /// The fallback must be a fallback, and must not be listed twice.
    ///
    /// An earlier version asserted no sovright node appeared before the tail
    /// of the list. That is not ours to control: these nodes are publicly
    /// reachable, so the DNS seeders now advertise them, and one arriving
    /// mid-list through the seeders is the open network working rather than
    /// a bug. What Argos controls is that it does not *prioritise* them and
    /// does not add a duplicate — a second copy of one host would spend two
    /// slots of a batch sized for distinct peers.
    #[tokio::test]
    async fn sovright_nodes_are_appended_once_and_never_prioritised() {
        let Ok(seeds) = resolve_seeds(P2pNetwork::Mainnet).await else {
            // No DNS in this environment; nothing to order.
            return;
        };

        for node in SOVRIGHT_MAINNET_NODES {
            assert_eq!(
                seeds.iter().filter(|s| *s == node).count(),
                1,
                "{node} must appear exactly once, however it was sourced"
            );
        }

        // Any we appended ourselves sit at the very end; any the seeders
        // supplied keep whatever position the seeders gave them.
        let appended: Vec<&String> = seeds
            .iter()
            .rev()
            .take_while(|s| SOVRIGHT_MAINNET_NODES.contains(&s.as_str()))
            .collect();
        assert!(
            appended.len() <= SOVRIGHT_MAINNET_NODES.len(),
            "nothing but the fallback may be appended after the seeded peers"
        );
    }

    #[tokio::test]
    async fn testnet_gets_no_operator_fallback() {
        // Only mainnet nodes are run; seeding testnet with them would offer
        // peers that cannot serve that chain.
        let seeds = resolve_seeds(P2pNetwork::Testnet).await.unwrap_or_default();
        for node in SOVRIGHT_MAINNET_NODES {
            assert!(!seeds.contains(&(*node).to_owned()));
        }
    }

    #[tokio::test]
    async fn regtest_uses_only_the_addresses_it_is_given() {
        // No seeds exist for regtest, so with no explicit address there is
        // nothing to try and it must fail promptly rather than hang.
        let err = connect_to_any(P2pNetwork::Regtest, &[], 1)
            .await
            .expect_err("regtest with no address cannot connect");
        assert!(matches!(err, PoolError::AllPeersRefused { tried: 0, .. }));
    }
}
