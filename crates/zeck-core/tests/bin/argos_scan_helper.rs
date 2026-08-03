//! `argos-scan-helper` — test-only binary spawned as a subprocess by R-S27.
//!
//! The parent test (`crash_mid_scan_resumes_from_fully_scanned_height`)
//! launches this helper, watches its stdout for `{"event":"block", ...}`
//! lines, sends SIGKILL after a configured number of blocks have been
//! scanned, then re-launches the helper with the same `--data-dir` and
//! asserts the second run picks up from the persisted
//! `fully_scanned_height` instead of from `birthday`.
//!
//! Why a subprocess: in-process task cancellation does not exercise the
//! genuine "the process disappears between a batch's emit and its DB
//! commit" failure mode. Only SIGKILL on a separate process lands inside
//! that window.
//!
//! ## CLI
//!
//! ```bash
//! argos-scan-helper \
//!     --data-dir <path> \
//!     --lightwalletd-url <url> \
//!     [--birthday <height>] \
//!     [--num-accounts <n>] \
//!     [--gap-limit <n>] \
//!     [--label <s>]
//! ```
//!
//! The seed phrase is read from `ARGOS_TEST_SEED` (the same env var the
//! C2 test harness uses). Refusing to take the seed on the command line
//! avoids it leaking into process listings or shell history during local
//! debugging.
//!
//! ## stdout schema (one JSON object per line, flushed after each)
//!
//! ```text
//! {"event":"phase","phase":"<name>"}
//! {"event":"block","scanned_to":N}
//! {"event":"discovery","account_index":N,"pool":"transparent|sapling|orchard",
//!  "zatoshis":N,"address":"...","at_block_height":N}
//! {"event":"error","message":"..."}
//! {"event":"complete","total_zatoshis":N}
//! ```
//!
//! The helper flushes stdout after every line so the parent test can read
//! incrementally and decide when to SIGKILL.

#![cfg(feature = "argos-network")]

use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use argos_core::{RecoveryService, ScanConfig, ScanDiscovery, ScanPhase, ZeckNetwork};
// Shared with `argos_sweep_helper` and pulled in by path: a `[[bin]]`
// target cannot `use` the integration tests' `common` module.
#[path = "../common/regtest_consensus.rs"]
mod regtest_consensus;
use regtest_consensus::install_regtest_consensus_params;

use secrecy::SecretString;
use serde::Serialize;

#[derive(Debug)]
struct Args {
    data_dir: PathBuf,
    lightwalletd_url: String,
    birthday: u32,
    num_accounts: Option<u32>,
    gap_limit: u32,
    label: String,
}

fn parse_args() -> Args {
    let mut data_dir: Option<PathBuf> = None;
    let mut lightwalletd_url: Option<String> = None;
    let mut birthday: u32 = 1;
    let mut num_accounts: Option<u32> = Some(2);
    let mut gap_limit: u32 = 5;
    let mut label = String::from("scan-helper");

    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        match flag.as_str() {
            "--data-dir" => {
                data_dir = Some(PathBuf::from(
                    iter.next().expect("--data-dir needs a value"),
                ));
            }
            "--lightwalletd-url" => {
                lightwalletd_url = Some(iter.next().expect("--lightwalletd-url needs a value"));
            }
            "--birthday" => {
                birthday = iter
                    .next()
                    .expect("--birthday needs a value")
                    .parse()
                    .expect("--birthday must be a u32");
            }
            "--num-accounts" => {
                num_accounts = Some(
                    iter.next()
                        .expect("--num-accounts needs a value")
                        .parse()
                        .expect("--num-accounts must be a u32"),
                );
            }
            "--gap-limit" => {
                gap_limit = iter
                    .next()
                    .expect("--gap-limit needs a value")
                    .parse()
                    .expect("--gap-limit must be a u32");
            }
            "--label" => {
                label = iter.next().expect("--label needs a value");
            }
            other => {
                eprintln!("unrecognised flag: {other}");
                std::process::exit(2);
            }
        }
    }

    Args {
        data_dir: data_dir.expect("--data-dir is required"),
        lightwalletd_url: lightwalletd_url.expect("--lightwalletd-url is required"),
        birthday,
        num_accounts,
        gap_limit,
        label,
    }
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum HelperEvent<'a> {
    Phase {
        phase: &'a str,
    },
    Block {
        scanned_to: u64,
    },
    Discovery {
        account_index: u32,
        pool: &'a str,
        zatoshis: u64,
        address: &'a str,
        at_block_height: u64,
    },
    Error {
        message: &'a str,
    },
    Complete {
        total_zatoshis: u64,
    },
}

fn emit(event: &HelperEvent<'_>) {
    // Best-effort: a write failure here means the parent stopped reading,
    // typically because it just sent SIGKILL. Either way, nothing useful
    // to do but exit.
    let line = serde_json::to_string(event).expect("HelperEvent should always serialize");
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn pool_name(pool: argos_core::DiscoveryPool) -> &'static str {
    match pool {
        argos_core::DiscoveryPool::Transparent => "transparent",
        argos_core::DiscoveryPool::Sapling => "sapling",
        argos_core::DiscoveryPool::Orchard => "orchard",
    }
}

fn discovery_key(d: &ScanDiscovery) -> String {
    // Same shape the GUI's pump-loop uses: (pool, account, address) uniquely
    // identifies a discovery; height/zatoshis change as the scan refines.
    format!("{:?}|{}|{}", d.pool, d.account_index, d.address)
}

#[tokio::main]
async fn main() {
    install_regtest_consensus_params();

    let args = parse_args();
    let seed = std::env::var("ARGOS_TEST_SEED")
        .expect("ARGOS_TEST_SEED env var must be set (same contract as the C2 harness)");

    let scan_config = ScanConfig {
        birthday: args.birthday,
        num_accounts: args.num_accounts,
        gap_limit: args.gap_limit,
        lightwalletd_url: args.lightwalletd_url,
        data_dir: args.data_dir,
        network: ZeckNetwork::Testnet,
        label: args.label,
    };

    let service = RecoveryService::new();
    let handle = match service
        .start_scan(scan_config, SecretString::new(seed))
        .await
    {
        Ok(h) => h,
        Err(err) => {
            emit(&HelperEvent::Error {
                message: &err.to_string(),
            });
            std::process::exit(1);
        }
    };

    let mut last_phase: Option<ScanPhase> = None;
    let mut last_synced: Option<u64> = None;
    let mut seen_discoveries: HashSet<String> = HashSet::new();

    loop {
        let progress = match service.get_scan_progress(&handle).await {
            Ok(p) => p,
            Err(err) => {
                emit(&HelperEvent::Error {
                    message: &err.to_string(),
                });
                std::process::exit(1);
            }
        };

        // Phase transitions.
        if last_phase != Some(progress.phase) {
            emit(&HelperEvent::Phase {
                phase: phase_name(progress.phase),
            });
            last_phase = Some(progress.phase);
        }

        // Synced-to-height progress. Emit only when it advances.
        if let Some(synced) = progress.synced_to_height {
            if last_synced != Some(synced) {
                emit(&HelperEvent::Block { scanned_to: synced });
                last_synced = Some(synced);
            }
        }

        // New discoveries since last tick.
        for d in &progress.discoveries {
            let key = discovery_key(d);
            if seen_discoveries.insert(key) {
                emit(&HelperEvent::Discovery {
                    account_index: d.account_index,
                    pool: pool_name(d.pool),
                    zatoshis: d.zatoshis,
                    address: &d.address,
                    at_block_height: d.at_block_height,
                });
            }
        }

        match progress.phase {
            ScanPhase::Complete => {
                let total: u64 = progress.discoveries.iter().map(|d| d.zatoshis).sum();
                emit(&HelperEvent::Complete {
                    total_zatoshis: total,
                });
                return;
            }
            ScanPhase::Error => {
                let msg = progress
                    .error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "scan ended in Error with empty error field".to_owned());
                emit(&HelperEvent::Error { message: &msg });
                std::process::exit(1);
            }
            ScanPhase::Cancelled => {
                emit(&HelperEvent::Error {
                    message: "scan was cancelled",
                });
                std::process::exit(1);
            }
            _ => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

fn phase_name(p: ScanPhase) -> &'static str {
    match p {
        ScanPhase::Idle => "idle",
        ScanPhase::ValidatingSeed => "validating_seed",
        ScanPhase::DerivingKeys => "deriving_keys",
        ScanPhase::ProbingLightwalletd => "probing_lightwalletd",
        ScanPhase::ScanningTransparent => "scanning_transparent",
        ScanPhase::ScanningShielded => "scanning_shielded",
        ScanPhase::Complete => "complete",
        ScanPhase::Cancelled => "cancelled",
        ScanPhase::Error => "error",
    }
}
