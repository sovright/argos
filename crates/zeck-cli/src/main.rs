use std::{collections::VecDeque, fs, io::Write, path::PathBuf, time::{Duration, Instant}};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::process::Command;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use dialoguer::Password;
use indicatif::{ProgressBar, ProgressStyle};
use secrecy::SecretString;
use tracing_subscriber::EnvFilter;
use argos_core::{
    detect_birthday, derive_accounts, estimate_birthday_from_date, validate_destination_address,
    RecoveryService, ScanConfig, ScanDiscovery, ScanHandle, ScanPhase, SweepProposal, SweepRequest,
    ZeckNetwork,
};

#[derive(Debug, Parser)]
#[command(
    name = "argos",
    about = "Legacy ZecWallet Lite recovery tool",
    long_about = "Argos recovers funds from ZecWallet Lite wallets using a BIP-39 seed phrase.\n\
                  It derives keys, scans the Zcash blockchain via lightwalletd, and can sweep\n\
                  recovered funds to a new Unified Address.",
    version
)]
struct Cli {
    /// Path to a plain-text file containing the 24-word seed phrase. Must be
    /// chmod 600 (owner read/write only) on Unix.
    #[arg(long)]
    seed_file: Option<PathBuf>,

    /// Directory for wallet database and block cache.
    #[arg(long, default_value = "./argos_data")]
    data_dir: PathBuf,

    /// lightwalletd gRPC endpoint(s). Comma-separated URLs are tried in order.
    #[arg(
        long,
        visible_alias = "server",
        default_value = "https://mainnet.lightwalletd.com:9067"
    )]
    lightwalletd_url: String,

    /// Scan exactly this many accounts (overrides --gap-limit).
    #[arg(long)]
    num_accounts: Option<u32>,

    /// Stop after this many consecutive empty accounts (ignored when --num-accounts is set).
    #[arg(long, default_value_t = 20)]
    gap_limit: u32,

    /// Wallet birthday as a block height. Use 0 for a full scan from genesis.
    #[arg(long, default_value_t = 419_200)]
    birthday: u32,

    /// Wallet creation date (YYYY-MM-DD). Estimates birthday height automatically.
    #[arg(long, conflicts_with = "birthday_auto_detect")]
    birthday_date: Option<String>,

    /// Probe lightwalletd to auto-detect the wallet birthday from on-chain history.
    /// Supersedes --birthday and --birthday-date. Requires --lightwalletd-url.
    #[arg(long, conflicts_with = "birthday_date")]
    birthday_auto_detect: bool,

    /// Zcash network to use.
    #[arg(long, value_enum, default_value_t = NetworkArg::Mainnet)]
    network: NetworkArg,

    /// Enable debug-level logging from argos-core.
    #[arg(long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet,
}

impl From<NetworkArg> for ZeckNetwork {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Mainnet => ZeckNetwork::Mainnet,
            NetworkArg::Testnet => ZeckNetwork::Testnet,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Derive and display all account keys and addresses (no network needed).
    ShowKeys,

    /// Scan the blockchain and report balances for all derived accounts.
    Scan,

    /// Scan and then sweep recovered funds to a Unified Address.
    Sweep {
        /// Destination Unified Address (must include Orchard or Sapling receiver).
        #[arg(long)]
        destination: String,

        /// Optional memo attached to shielded outputs (max 512 bytes).
        #[arg(long)]
        memo: Option<String>,

        /// Fraction of recovered funds to donate to the project (e.g. 0.10 for 10%). Omit to skip.
        #[arg(long)]
        donation_rate: Option<f64>,

        /// Email placed in the donation memo for an off-chain receipt (optional).
        #[arg(long)]
        donor_email: Option<String>,

        /// Maximum fee in ZEC (e.g. 0.001). Sweep is skipped if estimated fee exceeds this.
        #[arg(long, value_parser = parse_zec_to_zatoshis)]
        max_fee: Option<u64>,

        /// Preview the sweep proposal without broadcasting any transactions.
        #[arg(long, conflicts_with = "confirm_sweep")]
        dry_run: bool,

        /// Confirm you understand this is irreversible and broadcast the sweep.
        #[arg(long)]
        confirm_sweep: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.verbose)?;

    let network: ZeckNetwork = cli.network.into();

    let seed_phrase = load_seed_phrase(cli.seed_file)?;

    let birthday = if cli.birthday_auto_detect {
        eprintln!("Auto-detecting wallet birthday from on-chain history…");
        let result = detect_birthday(
            &seed_phrase,
            network,
            &cli.lightwalletd_url,
            |msg| eprintln!("  {msg}"),
        )
        .await
        .context("birthday auto-detection failed")?;
        eprintln!("✓ {}", result.message);
        result.birthday
    } else if let Some(date) = &cli.birthday_date {
        estimate_birthday_from_date(date, &cli.lightwalletd_url).await?
    } else {
        cli.birthday
    };
    let account_count = cli.num_accounts.unwrap_or(20);

    if matches!(cli.command, Commands::Scan | Commands::Sweep { .. }) {
        eprintln!(
            "Note: this scan can take hours for old wallets. Progress is saved \
             under {data_dir} after each batch — interrupt with Ctrl-C any time \
             and re-run with the same --data-dir, --network, --birthday, and \
             account-scan mode (the same --gap-limit, or the same --num-accounts) \
             to resume from the last persisted block. Changing any of those \
             intentionally starts a fresh workspace and re-scans from the new \
             birthday.",
            data_dir = cli.data_dir.display(),
        );
    }

    match cli.command {
        Commands::ShowKeys => {
            let accounts = derive_accounts(&seed_phrase, network, account_count)?;
            for account in accounts {
                println!("━━━ Account {} ━━━", account.index);
                println!("  Unified address     {}", account.unified_address);
                println!("  Orchard path        {}", account.orchard_path);
                println!("  Sapling address     {}", account.sapling_address);
                println!("  Sapling path        {}", account.sapling_path);
                println!(
                    "  Transparent receive {}  ({})",
                    account.transparent_receive_address, account.transparent_receive_path
                );
                println!(
                    "  Transparent change  {}  ({})",
                    account.transparent_change_address, account.transparent_change_path
                );
                println!();
            }
        }

        Commands::Scan => {
            let service = RecoveryService::new();
            let handle = service
                .start_scan(
                    ScanConfig {
                        birthday,
                        num_accounts: cli.num_accounts,
                        gap_limit: cli.gap_limit,
                        lightwalletd_url: cli.lightwalletd_url.clone(),
                        data_dir: cli.data_dir.clone(),
                        network,
                        label: String::new(),
                    },
                    seed_phrase,
                )
                .await?;

            let progress = wait_for_scan(&service, &handle).await?;
            print_scan_result(&progress);
            notify_scan_complete(&progress);
            if progress.phase == ScanPhase::Cancelled {
                std::process::exit(130);
            }
            if progress.phase == ScanPhase::Error {
                bail!("recovery scan failed");
            }
        }

        Commands::Sweep {
            destination,
            memo,
            donation_rate,
            donor_email,
            max_fee,
            dry_run,
            confirm_sweep,
        } => {
            let address = validate_destination_address(&destination)?;
            println!(
                "Destination: Unified Address (Orchard={}, Sapling={}, Transparent={})",
                address.has_orchard, address.has_sapling, address.has_transparent
            );

            if dry_run {
                println!();
                println!("╔══════════════════════════════════════╗");
                println!("║  DRY RUN — no funds will be moved    ║");
                println!("╚══════════════════════════════════════╝");
                println!();
            }

            let service = RecoveryService::new();
            let handle = service
                .start_scan(
                    ScanConfig {
                        birthday,
                        num_accounts: cli.num_accounts,
                        gap_limit: cli.gap_limit,
                        lightwalletd_url: cli.lightwalletd_url.clone(),
                        data_dir: cli.data_dir.clone(),
                        network,
                        label: String::new(),
                    },
                    seed_phrase,
                )
                .await?;

            let progress = wait_for_scan(&service, &handle).await?;
            print_scan_result(&progress);
            notify_scan_complete(&progress);
            if progress.phase == ScanPhase::Cancelled {
                std::process::exit(130);
            }
            if progress.phase == ScanPhase::Error {
                bail!("recovery scan failed");
            }

            let request = SweepRequest {
                destination: destination.clone(),
                memo: memo.clone(),
                max_fee_zatoshis: max_fee,
                donation_rate,
                donor_email,
            };
            let proposal = service.propose_sweep(&handle, request.clone()).await?;
            print_sweep_preview(&proposal);

            if dry_run {
                println!();
                println!("Dry run complete. Re-run with --confirm-sweep to broadcast.");
                return Ok(());
            }

            if confirm_sweep {
                println!();
                println!("Broadcasting sweep transactions…");
                let execution = service.execute_sweep(&handle, request).await;
                match execution {
                    Ok(outcome) => {
                        println!();
                        for result in &outcome.transactions {
                            println!(
                                "  account {}  {}  {}",
                                result.source_account, result.status, result.detail
                            );
                        }
                        println!();
                        match outcome.error {
                            None => println!("Sweep complete."),
                            // A mid-sequence abort: the transactions above were
                            // already broadcast and are irreversible, but the
                            // remaining accounts were not swept (audit Issue E).
                            // Make this loud so the operator does not assume
                            // nothing was sent and retry into a double-broadcast.
                            Some(message) => {
                                eprintln!(
                                    "Sweep aborted after broadcasting the transactions listed \
                                     above. Those funds are already on-chain; the remaining \
                                     accounts were NOT swept. Rescan or check a block explorer \
                                     for the destination before retrying, to avoid broadcasting \
                                     duplicates."
                                );
                                eprintln!("Error: {message}");
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!();
                        eprintln!("Sweep failed: {err}");
                        std::process::exit(1);
                    }
                }
            } else {
                println!();
                println!("Re-run with --dry-run to preview, or --confirm-sweep to broadcast.");
            }
        }
    }

    Ok(())
}

fn init_tracing(verbose: bool) -> Result<()> {
    let filter = if verbose {
        EnvFilter::new("argos_core=debug,argos_cli=debug")
    } else {
        EnvFilter::new("warn")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .try_init()
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(())
}

fn load_seed_phrase(seed_file: Option<PathBuf>) -> Result<SecretString> {
    if let Some(path) = seed_file {
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to inspect seed file {}", path.display()))?;
        if !metadata.is_file() {
            bail!("seed file {} is not a regular file", path.display());
        }
        validate_seed_file_permissions(&path, &metadata)?;
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("failed to read seed file {}", path.display()))?;
        return Ok(SecretString::new(contents.trim().to_owned()));
    }

    let phrase = Password::new()
        .with_prompt("Enter your 24-word seed phrase")
        .allow_empty_password(false)
        .interact()
        .context("failed to read seed phrase from terminal")?;

    Ok(SecretString::new(phrase.trim().to_owned()))
}

fn validate_seed_file_permissions(path: &std::path::Path, metadata: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            bail!(
                "seed file {} is readable by group or other users; run `chmod 600 {}` first",
                path.display(),
                path.display()
            );
        }
    }

    #[cfg(not(unix))]
    {
        let _ = (path, metadata);
    }

    Ok(())
}

/// Parse a ZEC string (e.g. "0.001") into zatoshis.
fn parse_zec_to_zatoshis(input: &str) -> Result<u64, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("max fee cannot be empty".to_owned());
    }

    let (whole, fractional) = match trimmed.split_once('.') {
        Some((whole, frac)) => (whole, frac),
        None => (trimmed, ""),
    };

    if fractional.len() > 8 {
        return Err("max fee supports at most 8 decimal places".to_owned());
    }

    let whole_part = if whole.is_empty() {
        0u64
    } else {
        whole
            .parse::<u64>()
            .map_err(|_| "invalid whole ZEC amount".to_owned())?
    };

    let fractional_digits = if fractional.is_empty() {
        0u64
    } else {
        fractional
            .parse::<u64>()
            .map_err(|_| "invalid fractional ZEC amount".to_owned())?
    };

    let scale = 10u64.pow((8usize.saturating_sub(fractional.len())) as u32);
    whole_part
        .checked_mul(100_000_000)
        .and_then(|whole_zats| whole_zats.checked_add(fractional_digits.checked_mul(scale)?))
        .ok_or_else(|| "max fee is too large".to_owned())
}

/// Format zatoshis as a human-readable ZEC amount (e.g. "1.23456789 ZEC").
fn format_zec(zatoshis: u64) -> String {
    let whole = zatoshis / 100_000_000;
    let frac = zatoshis % 100_000_000;
    if frac == 0 {
        format!("{whole} ZEC")
    } else {
        format!("{whole}.{frac:08} ZEC")
    }
}

async fn wait_for_scan(
    service: &RecoveryService,
    handle: &ScanHandle,
) -> Result<argos_core::ScanProgress> {
    // Start with a spinner; upgrade to a real progress bar once we know total blocks.
    let bar = ProgressBar::new_spinner();
    bar.set_style(
        ProgressStyle::with_template("{spinner:.green} {msg}")?
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "),
    );
    bar.enable_steady_tick(Duration::from_millis(120));

    let mut bar_has_total = false;
    let mut eta = EtaTracker::new();
    let started_at = Instant::now();
    let mut discoveries_seen = 0usize;
    let mut sleep_events_announced: u32 = 0;
    let mut sandblasting_announced = false;
    let mut sandblasting_active = false;

    loop {
        let progress = service.get_scan_progress(handle).await?;

        // Surface any new discoveries above the progress bar so users see
        // "Found X ZEC on account N" the moment a refresh tick observes it,
        // instead of waiting for the scan to finish. The bar.println call
        // routes through indicatif so the progress bar is preserved on the
        // line below.
        //
        // Self-heal the cursor: the discovery log is contractually
        // append-only, but if a future bug ever shrinks it, clamp so we
        // don't index past the end and don't silently skip later events.
        if discoveries_seen > progress.discoveries.len() {
            discoveries_seen = progress.discoveries.len();
        }
        if progress.discoveries.len() > discoveries_seen {
            for d in &progress.discoveries[discoveries_seen..] {
                bar.println(format_discovery(d));
            }
            discoveries_seen = progress.discoveries.len();
        }

        // Announce each new sleep event. event_count is monotonic so we
        // print one line per resume, even if the user's machine sleeps
        // multiple times during a long scan.
        if let Some(event) = &progress.sleep_event {
            if event.event_count > sleep_events_announced {
                bar.println(format_sleep_event(event));
                sleep_events_announced = event.event_count;
            }
        }

        // Sandblasting era: warn on entry, reassure on exit. Heights are
        // mainnet-only; testnet always reports false.
        if progress.in_sandblasting_zone && !sandblasting_active {
            if !sandblasting_announced {
                bar.println(
                    "🐢  Entering sandblasting era (mainnet, ~mid-2022 → late 2023).\n    \
                     This window saw a sustained spam attack; sync through it can \
                     stretch to several days for old wallets.\n    \
                     As long as the block counter is moving, your scan is working as designed.\n    \
                     Background: https://www.theblock.co/post/175259/someone-is-clogging-up-the-zcash-blockchain-with-a-spam-attack",
                );
                sandblasting_announced = true;
            }
            sandblasting_active = true;
        } else if !progress.in_sandblasting_zone && sandblasting_active {
            bar.println("✅  Past the sandblasting window — sync should speed up from here.");
            sandblasting_active = false;
        }

        // Upgrade spinner → progress bar the first time we have block counts.
        if !bar_has_total && progress.blocks_total > 0 {
            bar.set_length(progress.blocks_total);
            bar.set_style(
                ProgressStyle::with_template(
                    "{spinner:.green} [{bar:40.cyan/blue}] {pos}/{len} blocks  {msg}",
                )?
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
                .progress_chars("█▉▊▋▌▍▎▏  "),
            );
            bar_has_total = true;
        }

        eta.observe(progress.blocks_scanned, progress.blocks_total);

        let phase_label = phase_label(&progress);
        let server_label = progress
            .server
            .as_ref()
            .map(|s| format!(" [{}]", s.endpoint))
            .unwrap_or_default();
        let eta_label = match eta.estimate(started_at.elapsed()) {
            EtaEstimate::Warmup => " · Estimating remaining time…".to_string(),
            EtaEstimate::Range(text) => format!(" · {text}"),
            EtaEstimate::Done => String::new(),
        };
        // era_hint expects an absolute Zcash chain height. blocks_scanned is
        // a delta from the effective birthday, so feeding it directly would
        // misreport the era for any wallet whose birthday is past Sapling
        // activation. Use synced_to_height (set by refresh_scan_progress and
        // the background incremental tick) when available.
        let era_label = progress
            .synced_to_height
            .and_then(era_hint)
            .map(|era| format!(" · scanning ~{era}"))
            .unwrap_or_default();

        let msg = format!("{phase_label}{server_label}{era_label}{eta_label}");

        if bar_has_total {
            bar.set_position(progress.blocks_scanned);
        }
        bar.set_message(msg);

        if progress.phase.is_terminal() {
            bar.finish_and_clear();
            return Ok(progress);
        }

        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

fn phase_label(progress: &argos_core::ScanProgress) -> String {
    match progress.phase {
        ScanPhase::Idle => "Starting".to_string(),
        ScanPhase::ValidatingSeed => "Validating seed".to_string(),
        ScanPhase::DerivingKeys => "Deriving keys".to_string(),
        ScanPhase::ProbingLightwalletd => "Connecting to lightwalletd".to_string(),
        ScanPhase::ScanningTransparent => "Scanning transparent addresses".to_string(),
        ScanPhase::ScanningShielded => "Decrypting shielded transactions".to_string(),
        ScanPhase::Complete => "Complete".to_string(),
        ScanPhase::Cancelled => "Cancelled".to_string(),
        ScanPhase::Error => "Error".to_string(),
    }
}

/// Sliding-window ETA tracker that ignores the noisy first few seconds and
/// returns a rounded range rather than a false-precision point estimate.
struct EtaTracker {
    samples: VecDeque<(Instant, u64)>,
    last_total: u64,
}

enum EtaEstimate {
    /// Not enough data yet — show a "Estimating…" message.
    Warmup,
    /// Stable estimate, formatted human-readably.
    Range(String),
    /// Either no work to do or already done.
    Done,
}

impl EtaTracker {
    const WARMUP: Duration = Duration::from_secs(15);
    const WINDOW: Duration = Duration::from_secs(45);

    fn new() -> Self {
        Self { samples: VecDeque::new(), last_total: 0 }
    }

    fn observe(&mut self, scanned: u64, total: u64) {
        if total == 0 {
            return;
        }
        self.last_total = total;
        let now = Instant::now();
        self.samples.push_back((now, scanned));
        let cutoff = now - Self::WINDOW;
        while let Some(&(t, _)) = self.samples.front() {
            if t < cutoff && self.samples.len() > 2 {
                self.samples.pop_front();
            } else {
                break;
            }
        }
    }

    fn estimate(&self, elapsed: Duration) -> EtaEstimate {
        let Some(&(t_first, blocks_first)) = self.samples.front() else {
            return EtaEstimate::Warmup;
        };
        let Some(&(t_last, blocks_last)) = self.samples.back() else {
            return EtaEstimate::Warmup;
        };
        if self.last_total == 0 {
            return EtaEstimate::Warmup;
        }

        let remaining = self.last_total.saturating_sub(blocks_last);
        if remaining == 0 {
            return EtaEstimate::Done;
        }

        let window = t_last.saturating_duration_since(t_first);
        let scanned_in_window = blocks_last.saturating_sub(blocks_first);
        if elapsed < Self::WARMUP || window < Duration::from_secs(5) || scanned_in_window < 50 {
            return EtaEstimate::Warmup;
        }

        let rate = scanned_in_window as f64 / window.as_secs_f64();
        if rate <= 0.0 {
            return EtaEstimate::Warmup;
        }

        let secs = (remaining as f64 / rate).round() as u64;
        EtaEstimate::Range(format_eta_range(secs))
    }
}

/// Returns a human-readable time range with rounding tuned to how uncertain we
/// expect each band to be. Falsifies precision deliberately — at 6h out, the
/// difference between 5h47m and 6h13m is meaningless to a waiting user.
fn format_eta_range(secs: u64) -> String {
    if secs < 60 {
        return "less than a minute remaining".to_string();
    }
    if secs < 5 * 60 {
        return "less than 5 minutes remaining".to_string();
    }
    if secs < 30 * 60 {
        let mins = ((secs as f64 / 60.0 / 5.0).round() as u64) * 5;
        return format!("about {mins} minutes remaining");
    }
    if secs < 60 * 60 {
        return "less than an hour remaining".to_string();
    }
    let hours = secs as f64 / 3600.0;
    if hours < 2.0 {
        return "about 1-2 hours remaining".to_string();
    }
    let lo = hours.floor() as u64;
    let hi = lo + 1;
    format!("about {lo}-{hi} hours remaining")
}

/// Map a block height to its approximate calendar year on mainnet so users can
/// feel the scan moving through time. Uses ~82 s/block long-run average from
/// Sapling activation (height 419,200, 2018-10-28).
fn era_hint(height: u64) -> Option<String> {
    if height == 0 {
        return None;
    }
    const SAPLING_HEIGHT: u64 = 419_200;
    const SAPLING_YEAR: i32 = 2018;
    const SECONDS_PER_BLOCK: f64 = 82.0;
    if height < SAPLING_HEIGHT {
        return Some("pre-Sapling era".to_string());
    }
    let elapsed_secs = (height - SAPLING_HEIGHT) as f64 * SECONDS_PER_BLOCK;
    let elapsed_years = elapsed_secs / (365.25 * 86_400.0);
    // Sapling activated late October — round forward so blocks shortly after
    // activation read as 2019, not 2018.
    let year = SAPLING_YEAR + (elapsed_years + 0.18) as i32;
    Some(year.to_string())
}

fn format_sleep_event(event: &argos_core::SleepEvent) -> String {
    let slept = format_local_hhmm(event.slept_at_unix);
    let resumed = format_local_hhmm(event.resumed_at_unix);
    let count_note = if event.event_count > 1 {
        format!(
            " ({} sleeps so far, total {} not syncing)",
            event.event_count,
            format_duration_secs(event.total_lost_seconds)
        )
    } else {
        String::new()
    };
    format!(
        "⏸  Detected that this machine slept from {slept}, restarted at {resumed}. \
         Time spent not syncing: {}{count_note}. \
         For faster sync, adjust your system settings to keep the computer awake while Argos runs.",
        format_duration_secs(event.last_sleep_seconds),
    )
}

/// Format a Unix timestamp as UTC HH:MM. The CLI deliberately stays in UTC
/// to avoid pulling in chrono for tz handling — the GUI does proper local-
/// time formatting via the browser's Intl API. CLI users running multi-hour
/// scans care more about "how long ago" than literal local-time formatting.
fn format_local_hhmm(unix_seconds: u64) -> String {
    let secs_in_day = unix_seconds % 86_400;
    let hours = secs_in_day / 3_600;
    let mins = (secs_in_day % 3_600) / 60;
    format!("{hours:02}:{mins:02} UTC")
}

fn format_duration_secs(secs: u64) -> String {
    let hours = secs / 3_600;
    let mins = (secs % 3_600) / 60;
    if hours > 0 {
        format!("{hours}h {mins:02}m")
    } else {
        format!("{mins}m {:02}s", secs % 60)
    }
}

fn format_discovery(discovery: &ScanDiscovery) -> String {
    // `at_block_height` is the scan frontier when the discovery was first
    // observed — not the transaction's mined height. Label accordingly so
    // users don't read it as transaction provenance.
    format!(
        "[scanned through block {}] account {}  +{} {}",
        discovery.at_block_height,
        discovery.account_index,
        format_zec(discovery.zatoshis),
        discovery.pool.label(),
    )
}

fn print_scan_result(progress: &argos_core::ScanProgress) {
    println!("Phase: {:?}", progress.phase);

    if let Some(error) = &progress.error {
        eprintln!("Error: {error}");
    }

    if let Some(server) = &progress.server {
        println!(
            "lightwalletd: {}  tip={}  vendor={}",
            server.endpoint,
            server.latest_block_height.unwrap_or_default(),
            server.vendor.as_deref().unwrap_or("unknown")
        );
    }

    if let Some(summary) = &progress.summary {
        println!("Authoritative balances: {}", summary.authoritative_balances);
        println!("Workspace: {}", summary.workspace_dir);
        if !summary.note.is_empty() {
            println!("Note: {}", summary.note);
        }
    }

    if progress.accounts.is_empty() {
        println!("No accounts derived.");
        return;
    }

    println!();
    println!("{:<8}  {:>16}  {:>16}  {:>16}  Status", "Account", "Sapling", "Orchard", "Transparent");
    println!("{}", "─".repeat(80));
    for account in &progress.accounts {
        println!(
            "{:<8}  {:>16}  {:>16}  {:>16}  {}",
            account.account_index,
            format_zec(account.sapling_zatoshis),
            format_zec(account.orchard_zatoshis),
            format_zec(account.transparent_zatoshis),
            account.status,
        );
    }
    println!("{}", "─".repeat(80));
    let total: u64 = progress.accounts.iter().map(|a| a.total_zatoshis).sum();
    println!("{:<8}  {:>52}  Total: {}", "", "", format_zec(total));
    println!();
    for account in &progress.accounts {
        if account.total_zatoshis > 0 {
            println!("Account {}  addresses:", account.account_index);
            println!("  Unified:              {}", account.unified_address);
            println!("  Sapling:              {}", account.sapling_address);
            println!("  Transparent receive:  {}", account.transparent_receive_address);
            println!("  Transparent change:   {}", account.transparent_change_address);
            println!();
        }
    }
}

fn print_sweep_preview(proposal: &SweepProposal) {
    println!();
    println!("Sweep preview:");
    println!("  Send:        {}", format_zec(proposal.total_send_zatoshis));
    println!("  Fee:         {}", format_zec(proposal.total_fee_zatoshis));
    println!("  Net receive: {}", format_zec(proposal.net_received_zatoshis));

    if !proposal.transactions.is_empty() {
        println!();
        println!("  Transactions:");
        for tx in &proposal.transactions {
            let memo = tx.memo.as_deref().unwrap_or("—");
            println!(
                "    account {:>3}  {:?}  gross={}  fee={}  net={}  memo={}",
                tx.source_account,
                tx.kind,
                format_zec(tx.gross_zatoshis),
                format_zec(tx.fee_zatoshis),
                format_zec(tx.net_zatoshis),
                memo,
            );
        }
    }

    if !proposal.skipped_accounts.is_empty() {
        println!();
        println!("  Skipped accounts:");
        for skipped in &proposal.skipped_accounts {
            println!(
                "    account {:>3}  gross={}  reason={}",
                skipped.account_index,
                format_zec(skipped.gross_zatoshis),
                skipped.reason,
            );
        }
    }

    if let Some(warning) = &proposal.warning {
        println!();
        println!("  Warning: {warning}");
    }
}

/// Try to grab the user's attention when a long-running scan finishes. Best
/// effort: terminal bell always; OS-level notification on macOS/Linux when the
/// usual platform tools are present. Errors are silently swallowed because the
/// scan succeeded — failing to notify is not a scan failure.
fn notify_scan_complete(progress: &argos_core::ScanProgress) {
    let title = match progress.phase {
        ScanPhase::Complete => "Argos scan complete",
        ScanPhase::Cancelled => "Argos scan cancelled",
        ScanPhase::Error => "Argos scan failed",
        _ => return,
    };

    let body = scan_completion_summary(progress);

    // Terminal bell. ANSI BEL is ignored by quiet terminals but harmless.
    let _ = std::io::stderr().write_all(b"\x07");

    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification {body} with title {title}",
            title = applescript_quote(title),
            body = applescript_quote(&body),
        );
        let _ = Command::new("osascript").arg("-e").arg(script).status();
    }

    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("notify-send").arg(title).arg(&body).status();
    }

    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms;\
             $n=[System.Windows.Forms.NotifyIcon]::new();\
             $n.Icon=[System.Drawing.SystemIcons]::Information;\
             $n.Visible=$true;\
             $n.ShowBalloonTip(5000,{title},{body},0);\
             Start-Sleep 2;\
             $n.Dispose()",
            title = powershell_quote(title),
            body = powershell_quote(&body),
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status();
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (title, body);
    }
}

fn scan_completion_summary(progress: &argos_core::ScanProgress) -> String {
    if let Some(error) = &progress.error {
        return error.clone();
    }
    // Reserve "no funds were found" for actually-completed scans. A
    // cancelled scan that hadn't yet observed any funds shouldn't claim
    // the seed is empty — it just stopped early.
    if progress.phase == ScanPhase::Cancelled {
        return "Scan stopped before completion. Re-run with the same flags to resume."
            .to_string();
    }
    let funded: Vec<_> = progress
        .accounts
        .iter()
        .filter(|a| a.total_zatoshis > 0)
        .collect();
    let total: u64 = funded.iter().map(|a| a.total_zatoshis).sum();
    if funded.is_empty() {
        return "No funds were found across all scanned accounts.".to_string();
    }
    let zec = format_zec(total);
    match funded.len() {
        1 => format!("Found {zec} on 1 account."),
        n => format!("Found {zec} across {n} accounts."),
    }
}

#[cfg(target_os = "macos")]
fn applescript_quote(input: &str) -> String {
    // AppleScript string literal: wrap in double quotes, escape backslashes
    // and double quotes. Strip control chars to keep `osascript` happy.
    let escaped: String = input
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '\\' => "\\\\".to_string(),
            '"' => "\\\"".to_string(),
            other => other.to_string(),
        })
        .collect();
    format!("\"{escaped}\"")
}

#[cfg(target_os = "windows")]
fn powershell_quote(input: &str) -> String {
    // PowerShell single-quoted string: only single-quotes need escaping (doubled).
    // Strip control chars to avoid shell injection.
    let escaped: String = input
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '\'' { "''".to_string() } else { c.to_string() })
        .collect();
    format!("'{escaped}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_zatoshi() {
        assert_eq!(parse_zec_to_zatoshis("0.00000001").unwrap(), 1);
    }

    #[test]
    fn whole_zec() {
        assert_eq!(parse_zec_to_zatoshis("1").unwrap(), 100_000_000);
    }

    #[test]
    fn mixed() {
        assert_eq!(parse_zec_to_zatoshis("0.0002").unwrap(), 20_000);
    }

    #[test]
    fn leading_dot() {
        assert_eq!(parse_zec_to_zatoshis(".5").unwrap(), 50_000_000);
    }

    #[test]
    fn too_many_decimals_rejected() {
        assert!(parse_zec_to_zatoshis("0.999999999").is_err());
    }

    #[test]
    fn negative_rejected() {
        assert!(parse_zec_to_zatoshis("-0.001").is_err());
    }

    #[test]
    fn empty_rejected() {
        assert!(parse_zec_to_zatoshis("").is_err());
    }

    #[test]
    fn non_numeric_rejected() {
        assert!(parse_zec_to_zatoshis("abc").is_err());
    }

    #[test]
    fn overflow_rejected() {
        assert!(parse_zec_to_zatoshis("99999999999999999999").is_err());
    }

    #[test]
    fn eta_under_a_minute_is_friendly() {
        assert_eq!(format_eta_range(45), "less than a minute remaining");
    }

    #[test]
    fn eta_under_five_minutes_is_friendly() {
        assert_eq!(format_eta_range(180), "less than 5 minutes remaining");
    }

    #[test]
    fn eta_minute_band_rounds_to_five() {
        // 7 minutes → "about 5 minutes remaining" (rounded down to nearest 5)
        assert_eq!(format_eta_range(7 * 60), "about 5 minutes remaining");
        // 13 minutes → "about 15 minutes remaining"
        assert_eq!(format_eta_range(13 * 60), "about 15 minutes remaining");
    }

    #[test]
    fn eta_under_an_hour_is_friendly() {
        assert_eq!(format_eta_range(45 * 60), "less than an hour remaining");
    }

    #[test]
    fn eta_short_hour_band_is_a_one_to_two() {
        assert_eq!(format_eta_range(80 * 60), "about 1-2 hours remaining");
    }

    #[test]
    fn eta_multi_hour_band_is_a_one_hour_window() {
        assert_eq!(format_eta_range(3 * 3600 + 1800), "about 3-4 hours remaining");
        assert_eq!(format_eta_range(7 * 3600), "about 7-8 hours remaining");
    }

    #[test]
    fn era_hint_for_genesis_is_pre_sapling() {
        assert_eq!(era_hint(100_000).as_deref(), Some("pre-Sapling era"));
    }

    #[test]
    fn era_hint_just_after_activation_is_2018() {
        assert_eq!(era_hint(420_000).as_deref(), Some("2018"));
    }

    #[test]
    fn era_hint_for_recent_height_is_recent_year() {
        // Block ~3.3M corresponds to ~2026.
        let era = era_hint(3_300_000).unwrap();
        assert!(
            era == "2025" || era == "2026",
            "expected 2025/2026 for height 3.3M, got {era}"
        );
    }

    #[test]
    fn era_hint_zero_is_none() {
        assert!(era_hint(0).is_none());
    }

    #[test]
    fn completion_summary_no_funds() {
        let progress = make_progress(ScanPhase::Complete, &[]);
        assert_eq!(
            scan_completion_summary(&progress),
            "No funds were found across all scanned accounts."
        );
    }

    #[test]
    fn cancelled_scan_does_not_claim_no_funds() {
        // Regression: an early Ctrl-C used to send a notification body of
        // "No funds were found..." even though the scan never finished.
        let progress = make_progress(ScanPhase::Cancelled, &[]);
        assert_eq!(
            scan_completion_summary(&progress),
            "Scan stopped before completion. Re-run with the same flags to resume."
        );
    }

    #[test]
    fn cancelled_scan_with_partial_funds_still_signals_incomplete() {
        // Even if some funds were observed before cancellation, the body
        // should make clear the scan didn't finish.
        let progress = make_progress(ScanPhase::Cancelled, &[(0, 50_000_000)]);
        assert_eq!(
            scan_completion_summary(&progress),
            "Scan stopped before completion. Re-run with the same flags to resume."
        );
    }

    #[test]
    fn completion_summary_one_account() {
        let progress = make_progress(ScanPhase::Complete, &[(0, 50_000_000)]);
        assert_eq!(
            scan_completion_summary(&progress),
            "Found 0.50000000 ZEC on 1 account."
        );
    }

    #[test]
    fn completion_summary_multiple_accounts() {
        let progress = make_progress(
            ScanPhase::Complete,
            &[(0, 100_000_000), (3, 50_000_000)],
        );
        assert_eq!(
            scan_completion_summary(&progress),
            "Found 1.50000000 ZEC across 2 accounts."
        );
    }

    #[test]
    fn completion_summary_uses_error_when_present() {
        let mut progress = make_progress(ScanPhase::Error, &[]);
        progress.error = Some("lightwalletd unreachable".to_string());
        assert_eq!(
            scan_completion_summary(&progress),
            "lightwalletd unreachable"
        );
    }

    fn make_progress(
        phase: ScanPhase,
        funded: &[(u32, u64)],
    ) -> argos_core::ScanProgress {
        let accounts = funded
            .iter()
            .map(|(idx, amount)| argos_core::AccountBalancePreview {
                account_index: *idx,
                sapling_address: String::new(),
                unified_address: String::new(),
                transparent_receive_address: String::new(),
                transparent_change_address: String::new(),
                transparent_utxo_count: 0,
                sapling_zatoshis: 0,
                orchard_zatoshis: *amount,
                transparent_zatoshis: 0,
                total_zatoshis: *amount,
                has_activity: true,
                status: String::new(),
            })
            .collect();
        argos_core::ScanProgress {
            handle: argos_core::ScanHandle::new(),
            phase,
            blocks_scanned: 0,
            blocks_total: 0,
            synced_to_height: None,
            elapsed_seconds: None,
            estimated_remaining_seconds: None,
            accounts,
            discoveries: vec![],
            summary: None,
            server: None,
            message: None,
            error: None,
            sleep_event: None,
            in_sandblasting_zone: false,
        }
    }

    #[test]
    fn format_zec_whole() {
        assert_eq!(format_zec(100_000_000), "1 ZEC");
    }

    #[test]
    fn format_zec_fractional() {
        assert_eq!(format_zec(50_000_000), "0.50000000 ZEC");
    }

    #[test]
    fn format_zec_one_zatoshi() {
        assert_eq!(format_zec(1), "0.00000001 ZEC");
    }

    #[test]
    fn format_zec_zero() {
        assert_eq!(format_zec(0), "0 ZEC");
    }

    #[test]
    fn format_zec_large() {
        assert_eq!(format_zec(2_100_000_000_000_000), "21000000 ZEC");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn powershell_quote_simple() {
        assert_eq!(powershell_quote("hello"), "'hello'");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn powershell_quote_single_quote_escaped() {
        assert_eq!(powershell_quote("it's done"), "'it''s done'");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn powershell_quote_strips_control_chars() {
        assert_eq!(powershell_quote("abc\x00def"), "'abcdef'");
    }
}