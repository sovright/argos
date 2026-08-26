//! `argos-sweep-helper` — test-only binary spawned as a subprocess by R-S29.
//!
//! The parent test (`crash_mid_broadcast_does_not_double_spend_on_resume`)
//! launches this helper against a multi-account-funded harness, watches its
//! stdout for the first `{"event":"broadcast", ...}` line, then sends SIGKILL
//! while the helper is sleeping in `--pause-millis-between-broadcasts`. The
//! parent then re-launches the helper and asserts:
//!
//!   1. The broadcast txid from the killed run is still in the wallet DB
//!      (no double-spend on resume).
//!   2. The second broadcast for the as-yet-unswept account proceeds.
//!
//! Why a subprocess + library pause: the per-account broadcast loop lives
//! inside `argos_core::RecoveryService::execute_sweep`. Without a hook the
//! helper cannot sit in the gap between two broadcasts for the SIGKILL to
//! land deterministically. The hook
//! (`RecoveryService::execute_sweep_with_test_pause`) is feature-gated on
//! `argos-network`, so released binaries do not carry the parameter.
//!
//! ## CLI
//!
//! ```bash
//! argos-sweep-helper \
//!     --data-dir <path> \
//!     --lightwalletd-url <url> \
//!     --destination-ua <u1...> \
//!     [--birthday <height>] \
//!     [--num-accounts <n>] \
//!     [--gap-limit <n>] \
//!     [--label <s>] \
//!     [--pause-millis-between-broadcasts <m>]
//! ```
//!
//! Seed is read from `ARGOS_TEST_SEED`. Donation is unconditionally disabled
//! on testnet (matches production behaviour at
//! `service.rs:effective_donation_address`), which keeps R-S29's assertions
//! focused on the no-double-spend property rather than on donation memo
//! semantics.
//!
//! ## stdout schema (one JSON object per line, flushed after each)
//!
//! Same scan-phase events as `argos-scan-helper`, plus, after scan complete:
//!
//! ```text
//! {"event":"sweep_starting"}
//! {"event":"broadcast","account_index":N,"txid":"<hex>","sent_zatoshis":N,"fee_zatoshis":N}
//! {"event":"sweep_complete","broadcast_count":N}
//! {"event":"error","message":"..."}
//! ```

#![cfg(feature = "argos-network")]

use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use argos_core::{
    RecoveryService, ScanConfig, ScanDiscovery, ScanPhase, SweepRequest, ZeckNetwork,
};
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
    destination_ua: String,
    birthday: u32,
    num_accounts: Option<u32>,
    gap_limit: u32,
    label: String,
    pause_millis_between_broadcasts: u64,
}

fn parse_args() -> Args {
    let mut data_dir: Option<PathBuf> = None;
    let mut lightwalletd_url: Option<String> = None;
    let mut destination_ua: Option<String> = None;
    let mut birthday: u32 = 1;
    let mut num_accounts: Option<u32> = Some(2);
    let mut gap_limit: u32 = 5;
    let mut label = String::from("sweep-helper");
    let mut pause_millis: u64 = 0;

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
            "--destination-ua" => {
                destination_ua = Some(iter.next().expect("--destination-ua needs a value"));
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
            "--pause-millis-between-broadcasts" => {
                pause_millis = iter
                    .next()
                    .expect("--pause-millis-between-broadcasts needs a value")
                    .parse()
                    .expect("--pause-millis-between-broadcasts must be a u64");
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
        destination_ua: destination_ua.expect("--destination-ua is required"),
        birthday,
        num_accounts,
        gap_limit,
        label,
        pause_millis_between_broadcasts: pause_millis,
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
    ScanComplete {
        total_zatoshis: u64,
    },
    SweepStarting,
    Broadcast {
        source_account: u32,
        txid: Option<&'a str>,
        status: &'a str,
        detail: &'a str,
        confirmed_height: Option<u32>,
    },
    SweepComplete {
        broadcast_count: usize,
    },
    Error {
        message: &'a str,
    },
}

fn emit(event: &HelperEvent<'_>) {
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
    format!("{:?}|{}|{}", d.pool, d.account_index, d.address)
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

    // ─── Scan phase: emit progress until Complete or Error ─────────────────
    let mut last_phase: Option<ScanPhase> = None;
    let mut last_synced: Option<u64> = None;
    let mut seen_discoveries: HashSet<String> = HashSet::new();

    let scan_total = loop {
        let progress = match service.get_scan_progress(&handle).await {
            Ok(p) => p,
            Err(err) => {
                emit(&HelperEvent::Error {
                    message: &err.to_string(),
                });
                std::process::exit(1);
            }
        };

        if last_phase != Some(progress.phase) {
            emit(&HelperEvent::Phase {
                phase: phase_name(progress.phase),
            });
            last_phase = Some(progress.phase);
        }

        if let Some(synced) = progress.synced_to_height {
            if last_synced != Some(synced) {
                emit(&HelperEvent::Block { scanned_to: synced });
                last_synced = Some(synced);
            }
        }

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
                emit(&HelperEvent::ScanComplete {
                    total_zatoshis: total,
                });
                break total;
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
    };

    if scan_total == 0 {
        // Nothing to sweep — surface it as an error so the test fails loudly.
        emit(&HelperEvent::Error {
            message: "scan completed with zero balance — setup.sh did not fund the test seed",
        });
        std::process::exit(1);
    }

    // ─── Sweep phase: feature-gated test-only entrypoint with per-account pause ─
    emit(&HelperEvent::SweepStarting);

    let sweep_request = SweepRequest {
        destination: args.destination_ua,
        memo: None,
        max_fee_zatoshis: None,
        donation_rate: None,
        donor_email: None,
    };

    // NB: the helper's broadcast event is emitted only *after* the per-account
    // broadcast lands in the result list. The library's pause happens after
    // the broadcast returns and before the next account begins — so the parent
    // observes the broadcast event, then has `pause_millis_between_broadcasts`
    // to deliver SIGKILL before the next account is processed.
    //
    // We can't interleave a callback because `execute_sweep_with_test_pause`
    // returns a `SweepOutcome` only at the end. So we emit the broadcast events
    // here after the sweep returns. For the SIGKILL test this is fine: the kill
    // lands during the library's sleep, before the second broadcast happens, so
    // the second broadcast is never produced and the loop never completes. The
    // first broadcast's effect on the wallet DB is already committed before the
    // sleep, which is exactly the invariant the test verifies.
    //
    // A `SweepOutcome` carries `transactions` on both full success and a
    // mid-sequence abort (audit Issue E); only a failure before any broadcast
    // is an `Err`. Emit the broadcast records in either case.
    let pause = Duration::from_millis(args.pause_millis_between_broadcasts);
    let outcome = match service
        .execute_sweep_with_test_pause(&handle, sweep_request, pause)
        .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            emit(&HelperEvent::Error {
                message: &err.to_string(),
            });
            std::process::exit(1);
        }
    };

    for r in &outcome.transactions {
        emit(&HelperEvent::Broadcast {
            source_account: r.source_account,
            txid: r.txid.as_deref(),
            status: &r.status,
            detail: &r.detail,
            confirmed_height: r.confirmed_height,
        });
    }

    if let Some(message) = &outcome.error {
        emit(&HelperEvent::Error { message });
    }

    emit(&HelperEvent::SweepComplete {
        broadcast_count: outcome.transactions.len(),
    });
}
