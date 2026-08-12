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
    #[error(
        "no Zcash peer would accept a connection. {refused} of {tried} peers refused a \
         connection slot, which is normal when the network is busy — retrying usually \
         succeeds. ({other} failed for other reasons.)"
    )]
    AllPeersRefused {
        tried: usize,
        refused: usize,
        other: usize,
    },
    #[error(
        "could not resolve any Zcash DNS seed ({0}). This usually means no internet \
         connection, or DNS is blocked on this network."
    )]
    NoSeedsResolved(String),
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
    if matches!(network, P2pNetwork::Mainnet) {
        resolved.extend(SOVRIGHT_MAINNET_NODES.iter().map(|s| (*s).to_owned()));
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
async fn race_batch(candidates: &[String], network: P2pNetwork) -> (Option<Peer>, usize, usize) {
    let mut set = tokio::task::JoinSet::new();
    for addr in candidates {
        let addr = addr.clone();
        set.spawn(async move { Peer::connect(&addr, network).await });
    }

    let mut refused = 0;
    let mut other = 0;
    while let Some(joined) = set.join_next().await {
        match joined {
            Ok(Ok(peer)) => {
                // Dropping the set aborts the rest.
                return (Some(peer), refused, other);
            }
            Ok(Err(err)) => {
                if is_slot_refusal(&err) {
                    refused += 1;
                } else {
                    other += 1;
                }
            }
            Err(_) => other += 1,
        }
    }
    (None, refused, other)
}

/// Whether an error is a peer declining to give us a connection slot, as
/// opposed to something wrong on our side.
///
/// Both present as a failed connection, but only this kind is routine and
/// worth retrying, so they are counted separately and reported separately.
fn is_slot_refusal(err: &PeerError) -> bool {
    match err {
        PeerError::Closed => true,
        PeerError::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionAborted
        ),
        PeerError::Connect { source, .. } => matches!(
            source.kind(),
            std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::TimedOut
        ),
        PeerError::Timeout { .. } => true,
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
    let mut refused = 0;
    let mut other = 0;

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

        let (peer, r, o) = race_batch(batch, network).await;
        refused += r;
        other += o;
        if let Some(peer) = peer {
            return Ok(peer);
        }

        // A short pause between rounds: the refusals are capacity-driven, so
        // immediately retrying the same hosts is both rude and pointless.
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    Err(PoolError::AllPeersRefused {
        tried,
        refused,
        other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The distinction the error message depends on. A peer declining a slot
    /// is routine; a checksum failure means something is rewriting our
    /// traffic, and telling a user to "just retry" would be wrong.
    #[test]
    fn slot_refusals_are_told_apart_from_real_faults() {
        assert!(is_slot_refusal(&PeerError::Closed));
        assert!(is_slot_refusal(&PeerError::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        ))));
        assert!(is_slot_refusal(&PeerError::Timeout {
            what: "a header".to_owned()
        }));

        assert!(!is_slot_refusal(&PeerError::Wire(
            super::super::wire::WireError::BadChecksum
        )));
        assert!(!is_slot_refusal(&PeerError::ProtocolTooOld(170_002)));
    }

    /// The failure message is the only thing a stuck user sees, so it has to
    /// say what happened and whether retrying is worth it.
    #[test]
    fn the_all_refused_error_explains_itself() {
        let err = PoolError::AllPeersRefused {
            tried: 38,
            refused: 35,
            other: 3,
        }
        .to_string();
        assert!(err.contains("38"));
        assert!(err.contains("35"));
        assert!(
            err.contains("retrying"),
            "a capacity refusal is routine and the user should be told to retry"
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

    /// The fallback must be a fallback. Putting these first would
    /// centralise every scan onto one operator by default, and would do it
    /// silently.
    #[tokio::test]
    async fn sovright_nodes_come_after_the_dns_seeds() {
        let Ok(seeds) = resolve_seeds(P2pNetwork::Mainnet).await else {
            // No DNS in this environment; nothing to order.
            return;
        };
        let first_sovright = seeds
            .iter()
            .position(|s| SOVRIGHT_MAINNET_NODES.contains(&s.as_str()));
        if let Some(at) = first_sovright {
            assert!(
                at >= seeds.len() - SOVRIGHT_MAINNET_NODES.len(),
                "the operator's own nodes must sit at the end of the seed list"
            );
        }
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
