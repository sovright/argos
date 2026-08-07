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

    if addrs.is_empty() {
        return Err(PoolError::NoSeedsResolved(if errors.is_empty() {
            "the seeds resolved to no addresses".to_owned()
        } else {
            errors.join("; ")
        }));
    }
    Ok(addrs.into_iter().collect())
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

    #[test]
    fn a_dns_failure_is_not_reported_as_peers_refusing() {
        let err = PoolError::NoSeedsResolved("dns down".to_owned()).to_string();
        assert!(err.contains("DNS"));
        assert!(
            !err.contains("refused"),
            "a resolution failure must not be blamed on peers"
        );
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
