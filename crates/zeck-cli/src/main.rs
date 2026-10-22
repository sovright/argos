#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::process::Command;
use std::{
    collections::VecDeque,
    ffi::OsString,
    fs,
    io::{IsTerminal, Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use argos_core::{
    argos_wallet_import::{self, ImportedKeys},
    derive_accounts, detect_birthday, estimate_birthday_from_date,
    imported::{encode_transparent_address, imported_transparent_keys},
    transparent_recovery::{
        quote_transparent_only, scan_transparent_only, sweep_transparent_only_from_quote,
        TransparentScanReport, TransparentSweepPlan,
    },
    validate_destination_address, ImportedKeySource, KeySource, RecoveryService, ScanConfig,
    ScanDiscovery, ScanHandle, ScanPhase, SeedKeySource, SweepProposal, SweepRequest, ZeckNetwork,
};
use argos_core::{
    p2p::wire::P2pNetwork, sprout_recovery::SpentEvidence, sprout_scan_cost::SproutScanCost,
};
use clap::{Parser, Subcommand, ValueEnum};
use dialoguer::Password;
use indicatif::{ProgressBar, ProgressStyle};
use secrecy::{ExposeSecret, Secret, SecretString};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "argos",
    about = "Legacy Zcash wallet recovery tool",
    long_about = "Argos recovers funds from ZecWallet Lite seeds and wallet files, zcashd \
                  wallet.dat files, and standalone Sapling or Sprout spending keys.\n\
                  It scans the Zcash blockchain through lightwalletd, or full blocks for \
                  Sprout, and sweeps recovered funds to a modern shielded address.",
    version
)]
// Every flag here is `global` so it parses on either side of the
// subcommand: the printed next-step hints (`argos scan-sprout --wallet-file …`)
// put it after, and users copy those verbatim.
struct Cli {
    /// Path to a plain-text file containing the BIP-39 seed phrase (12, 15,
    /// 18, 21 or 24 words). Must be chmod 600 (owner read/write only) on
    /// Unix.
    #[arg(long, global = true)]
    seed_file: Option<PathBuf>,

    /// Path to a legacy wallet file to recover keys from: a zcashd
    /// `wallet.dat` or a ZecWallet Lite wallet. Read-only — Argos never
    /// writes to this file. If the wallet is encrypted you are prompted
    /// for its passphrase; there is deliberately no flag for it, so it
    /// cannot land in shell history or `ps` output.
    #[arg(long, global = true, conflicts_with = "seed_file")]
    wallet_file: Option<PathBuf>,

    /// File holding a raw Sprout spending key (`SK…` mainnet / `ST…`
    /// testnet), one per line, for a key with no wallet file behind it.
    /// Read only by `scan-sprout`.
    ///
    /// A file rather than a flag, for the same reason the wallet passphrase
    /// is prompt-only: a spending key passed as an argument lands in shell
    /// history and in `ps` output for every user on the box (T-S6).
    #[arg(long, global = true)]
    sprout_key_file: Option<PathBuf>,

    /// File holding Sapling extended spending keys
    /// (`secret-extended-key-main1…` mainnet, `secret-extended-key-test1…`
    /// testnet), one per line, for keys with no wallet file behind them.
    ///
    /// A file rather than a flag value, for the same reason as
    /// `--sprout-key-file`: a spending key passed as an argument lands in
    /// shell history and in `ps` output for every user on the box (T-S6).
    ///
    /// Combinable with `--wallet-file`: a user may hold a wallet *and* a
    /// paper key for an address that wallet never knew about.
    #[arg(long, global = true, conflicts_with = "seed_file")]
    sapling_key_file: Option<PathBuf>,

    /// Directory for wallet database and block cache.
    #[arg(long, global = true, default_value = "./argos_data")]
    data_dir: PathBuf,

    /// lightwalletd gRPC endpoint(s). Comma-separated URLs are tried in order.
    /// Each must be https://, or http:// to localhost. The default is a
    /// mainnet server: with --network testnet, pass a testnet one such as
    /// https://testnet.zec.rocks:443.
    #[arg(
        long,
        global = true,
        visible_alias = "server",
        default_value = argos_core::lightwalletd::DEFAULT_MAINNET_LIGHTWALLETD
    )]
    lightwalletd_url: String,

    /// Independent transaction confirmation source, as operator-id=https://url.
    /// Repeat for each distinct operator. Localhost HTTP is allowed for tests.
    #[arg(long, global = true, action = clap::ArgAction::Append, value_name = "OPERATOR=URL")]
    confirmation_source: Vec<String>,

    /// Blocks downloaded and scanned at a time by `scan` and `sweep`. Trades
    /// speed for memory: a smaller batch holds fewer blocks and less
    /// decryption work at once, at the cost of more requests to lightwalletd.
    /// The default of 1000 suits most machines; on one with little RAM, or
    /// through the 2022 spam-era blocks, try 200 or 100. Clamped to 10–10000.
    #[arg(long, global = true, value_name = "BLOCKS")]
    scan_batch_size: Option<u32>,

    /// Scan exactly this many accounts (overrides --gap-limit). Also how many
    /// accounts show-keys prints (default 20). Seed sources only: an
    /// imported key set is scanned in full, one account per key.
    #[arg(long, global = true)]
    num_accounts: Option<u32>,

    /// Stop after this many consecutive empty accounts (ignored when --num-accounts is set).
    #[arg(long, global = true, default_value_t = 20)]
    gap_limit: u32,

    /// First index in the additional complete transparent range for HD seed
    /// sources. The range is imported for account 0 only: higher accounts
    /// get only the addresses the scan derives for them.
    #[arg(long, global = true, default_value_t = 0)]
    transparent_index_start: u32,

    /// Number of indices in the additional complete transparent range,
    /// counted from --transparent-index-start.
    #[arg(long, global = true, default_value_t = 1000)]
    transparent_index_count: u32,

    /// Also scan the transparent change branch for HD seed sources.
    #[arg(long, global = true)]
    transparent_change: bool,

    /// Wallet birthday as a block height [default: 419200]. For `scan` and
    /// `sweep`, the scan starts no earlier than one block past Sapling
    /// activation (419201 on mainnet), so the default and anything below it
    /// scan from 419201: the activation block itself is not scanned.
    /// Overridden by --birthday-date and --birthday-auto-detect.
    /// `scan-sprout` is not affected by that clamp: it always walks from
    /// height 1, and here --birthday can only lower the block it starts
    /// trial-decrypting from, never raise it.
    // No clap default: the Sprout scan must tell a height the user typed from
    // one they never gave. `birthday_or_default` supplies 419200 elsewhere.
    #[arg(long, global = true)]
    birthday: Option<u32>,

    /// Wallet creation date (YYYY-MM-DD). Estimates the birthday height from
    /// it, using lightwalletd. Overrides --birthday. Refused by `scan-sprout`,
    /// which takes --birthday <height> alone.
    #[arg(long, global = true, conflicts_with = "birthday_auto_detect")]
    birthday_date: Option<String>,

    /// Auto-detect the wallet birthday. Overrides --birthday; cannot be
    /// combined with --birthday-date. With a seed phrase (--seed-file, or a
    /// ZecWallet Lite wallet whose seed could be decrypted) it probes
    /// lightwalletd for on-chain history. With a zcashd wallet.dat it uses
    /// the file's key creation times, which can reach before Sapling; when
    /// some keys are undated it asks lightwalletd for the earliest unspent
    /// output of the file's transparent keys, which is only an upper bound
    /// on the wallet's age -- unless a Sapling key is undated, in which case
    /// there is no birthday and Sapling is scanned from activation. Refused
    /// by `scan-sprout`.
    #[arg(long, global = true, conflicts_with = "birthday_date")]
    birthday_auto_detect: bool,

    /// For `scan-sprout`: try to decrypt every block, ignoring the wallet
    /// file's Sprout key creation times. By default a wallet.dat whose
    /// Sprout keys are all dated skips trial decryption below the earliest
    /// of them (rounded down, with a margin); use this if those times may
    /// be wrong.
    #[arg(long, global = true)]
    no_birthday_skip: bool,

    /// Zcash network to use.
    #[arg(long, global = true, value_enum, default_value_t = NetworkArg::Mainnet)]
    network: NetworkArg,

    /// Enable debug-level logging from argos-core.
    #[arg(long, global = true)]
    verbose: bool,

    /// Accept the Argos Terms of Service non-interactively (for scripted/CI
    /// runs). Records acceptance under --data-dir without prompting.
    #[arg(long, global = true)]
    accept_tos: bool,

    #[command(subcommand)]
    command: Commands,
}

/// Clap's global Vec handling keeps only the values from the deepest command
/// when the same option is used on both sides of a subcommand. Recover the
/// source arguments in their original order after Clap validates the syntax.
fn parse_cli_from<I, T>(args: I) -> std::result::Result<Cli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
    let mut cli = Cli::try_parse_from(args.iter().cloned())?;
    let mut sources = Vec::new();
    let mut index = 1;
    while index < args.len() {
        let Some(arg) = args[index].to_str() else {
            index += 1;
            continue;
        };
        if arg == "--" {
            break;
        }
        if arg == "--confirmation-source" {
            if let Some(value) = args.get(index + 1).and_then(|value| value.to_str()) {
                sources.push(value.to_owned());
            }
            index += 2;
        } else {
            if let Some(value) = arg.strip_prefix("--confirmation-source=") {
                sources.push(value.to_owned());
            }
            index += 1;
        }
    }
    cli.confirmation_source = sources;
    Ok(cli)
}

impl Cli {
    /// `--birthday`, or Sapling activation when none was given.
    fn birthday_or_default(&self) -> u32 {
        self.birthday
            .unwrap_or(sapling_activation_height(self.network.into()))
    }
}

/// Sapling activation height: where a scan with no birthday starts.
fn sapling_activation_height(network: ZeckNetwork) -> u32 {
    match network {
        ZeckNetwork::Mainnet => 419_200,
        ZeckNetwork::Testnet => 280_000,
    }
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

fn transparent_scan_config(
    index_start: u32,
    index_count: u32,
    include_change: bool,
) -> Result<argos_core::TransparentScanConfig> {
    let config = argos_core::TransparentScanConfig {
        index_start,
        index_count,
        include_change,
    };
    config.validate()?;
    Ok(config)
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Derive and display each account's addresses and derivation paths from
    /// the seed phrase. Prints no keys; no network needed.
    ShowKeys,

    /// Report what Argos can read out of --wallet-file and/or
    /// --sapling-key-file. Purely local: no network, and nothing is written
    /// anywhere.
    InspectWallet {
        /// List each Sprout note the wallet already spent: its outpoint, its
        /// value, and the transaction that spent it.
        #[arg(long)]
        show_spent: bool,
    },

    /// Scan the blockchain and report balances for derived or imported keys.
    Scan,

    /// Scan and then sweep recovered funds to a Unified Address.
    Sweep {
        /// Destination Unified Address (must include an Orchard or Sapling
        /// receiver). Transparent funds from a wallet file with no seed phrase
        /// are swept into Sapling, so that destination needs a Sapling
        /// receiver.
        #[arg(long)]
        destination: String,

        /// Optional memo attached to shielded outputs (max 512 bytes). Sent
        /// only when sweeping from a seed phrase (--seed-file, or a ZecWallet
        /// Lite wallet whose seed could be decrypted); without --memo, that
        /// sweep still writes the memo "Argos recovery". Any other source
        /// sends no memo at all, so the sweep refuses one rather than drop
        /// it.
        #[arg(long)]
        memo: Option<String>,

        /// Fraction of recovered funds to donate to the project (e.g. 0.10 for
        /// 10%). Omit to skip. Sent only when sweeping from a seed phrase
        /// (--seed-file, or a ZecWallet Lite wallet whose seed could be
        /// decrypted) on mainnet. Otherwise no donation is sent.
        #[arg(long)]
        donation_rate: Option<f64>,

        /// Email placed in the donation memo for an off-chain receipt (optional).
        #[arg(long)]
        donor_email: Option<String>,

        /// Maximum total fee in ZEC across the whole sweep (e.g. 0.001).
        /// Checked before each transaction is broadcast. When the next one
        /// would take the total over, the sweep stops with an error, but
        /// transactions already broadcast for earlier accounts cannot be
        /// recalled.
        #[arg(long, value_parser = parse_zec_to_zatoshis)]
        max_fee: Option<u64>,

        /// Preview the sweep proposal without broadcasting any transactions.
        #[arg(long, conflicts_with = "confirm_sweep")]
        dry_run: bool,

        /// Confirm you understand this is irreversible and broadcast the sweep.
        #[arg(long)]
        confirm_sweep: bool,
    },

    /// Observe stored transactions through independent confirmation sources.
    /// A retry sends only the exact stored transaction bytes, never a new sweep.
    Reconcile {
        /// Observe one transaction id; omit to observe every stored transaction.
        #[arg(long)]
        txid: Option<String>,

        /// After observation, explicitly resubmit the exact stored transaction bytes.
        /// Requires --txid; only an unresolved submission is eligible.
        #[arg(long, requires = "txid")]
        resubmit: bool,
    },

    /// Find Sprout notes for wallet or standalone keys by scanning the chain.
    ///
    /// Takes keys from --sprout-key-file (a paper backup, or a `z_exportkey`
    /// string), --wallet-file, or both. There is no cheaper route: Sprout notes are
    /// discoverable only by trial-decrypting every JoinSplit, and no Sprout
    /// address index exists anywhere.
    ///
    /// Scans every block from height 1 to the chain tip, so notes received
    /// before Sapling activation are found, and so are Sprout notes created
    /// or spent after Canopy (Canopy only stopped new value entering
    /// Sprout). Every block is walked. For a wallet.dat whose Sprout keys
    /// all carry creation times, blocks before the earliest of them are not
    /// trial-decrypted; the scan says so and from which block, and
    /// --no-birthday-skip or a lower --birthday (which can only lower that
    /// block) turns it off. Expect days and hundreds of gigabytes of download (little
    /// disk: blocks are not kept). An interrupted scan resumes from its
    /// checkpoint under --data-dir, and re-running a finished one catches up
    /// to the new tip.
    ///
    /// A `wallet.dat` almost never needs this — its cached witnesses make
    /// `sweep-sprout` work with no scan at all.
    ScanSprout {
        /// Bare Sapling address, or a Unified Address with a Sapling receiver,
        /// to sweep to once the scan finishes. Omit to scan and report
        /// without moving anything. The sweep is broadcast through
        /// --lightwalletd-url.
        #[arg(long)]
        destination: Option<String>,

        /// A Zcash node to fetch blocks from, as `host:port` (zebrad or
        /// zcashd, usually port 8233). Repeatable. Tried alongside the
        /// public DNS-seed peers rather than instead of them: your peers are
        /// dialled in the first round, and whichever connects first is used.
        /// Later rounds try more DNS-seed peers and, on mainnet, four
        /// fallback nodes run by the Argos project. The peer that serves the
        /// scan sees which blocks are requested.
        #[arg(long)]
        peer: Vec<String>,

        /// Path to sprout-groth16.params (~725 MB). Only needed when sweeping.
        /// Defaults to the file named by $ARGOS_SPROUT_PARAMS, then
        /// ~/.zcash-params/sprout-groth16.params.
        #[arg(long)]
        sprout_params: Option<PathBuf>,

        /// Confirm you understand the sweep is irreversible and broadcast it.
        #[arg(long)]
        confirm_sweep: bool,
    },

    /// Move Sprout funds out of a legacy wallet file to a Sapling address.
    ///
    /// Separate from `sweep` because Sprout recovery shares nothing with the
    /// HD pipeline: the notes come from the wallet file rather than from a
    /// scan, and the transaction is assembled by hand because
    /// `zcash_primitives`' builder refuses Sprout outright.
    SweepSprout {
        /// Bare Sapling address, or a Unified Address with a Sapling receiver.
        /// The value always lands in Sapling because Sprout cannot share a
        /// transaction with Orchard. Broadcast through --lightwalletd-url,
        /// which must serve --network: the default is a mainnet server.
        #[arg(long)]
        destination: String,

        /// Path to sprout-groth16.params (~725 MB). Defaults to the file named
        /// by $ARGOS_SPROUT_PARAMS, then ~/.zcash-params/sprout-groth16.params.
        #[arg(long)]
        sprout_params: Option<PathBuf>,

        /// Show what would be swept without building or broadcasting.
        #[arg(long, conflicts_with = "confirm_sweep")]
        dry_run: bool,

        /// Confirm you understand this is irreversible and broadcast.
        #[arg(long)]
        confirm_sweep: bool,

        /// A Zcash node, as `host:port`, used to verify a saved full-block
        /// scan before its spend evidence is trusted. Repeatable.
        #[arg(long)]
        peer: Vec<String>,
    },
}

fn command_uses_birthday_inputs(command: &Commands) -> bool {
    matches!(command, Commands::Scan | Commands::Sweep { .. })
}

/// Commands that reach the network or move funds, and so require the Terms
/// of Service to have been accepted.
///
/// Separate from the birthday check: `sweep-sprout` needs no birthday but
/// does broadcast irreversibly, and was previously ungated for exactly that
/// reason.
fn command_requires_tos(command: &Commands) -> bool {
    if matches!(
        command,
        Commands::Scan | Commands::Sweep { .. } | Commands::Reconcile { .. }
    ) {
        return true;
    }
    if matches!(
        command,
        Commands::SweepSprout { .. } | Commands::ScanSprout { .. }
    ) {
        return true;
    }
    false
}

/// Refuse a key-source flag the chosen command never reads.
///
/// Every top-level flag is `global`, so clap accepts
/// `argos show-keys --sprout-key-file …` and would otherwise run without the
/// key, leaving the user believing it was checked. Scan-tuning flags
/// (`--birthday`, `--gap-limit`, …) are deliberately not policed here:
/// ignoring one cannot misdirect funds, and `show-keys` accepts them for
/// compatibility.
fn refuse_unconsumed_key_sources(cli: &Cli) -> Result<()> {
    let (name, reads_seed, reads_wallet, reads_sapling, reads_sprout) = match &cli.command {
        Commands::ShowKeys => ("show-keys", true, true, true, false),
        Commands::InspectWallet { .. } => ("inspect-wallet", false, true, true, false),
        Commands::Scan => ("scan", true, true, true, false),
        Commands::Sweep { .. } => ("sweep", true, true, true, false),
        Commands::Reconcile { .. } => ("reconcile", false, false, false, false),
        Commands::ScanSprout { .. } => ("scan-sprout", false, true, false, true),
        Commands::SweepSprout { .. } => ("sweep-sprout", false, true, false, false),
    };
    let supplied = [
        ("--seed-file", cli.seed_file.is_some(), reads_seed),
        ("--wallet-file", cli.wallet_file.is_some(), reads_wallet),
        (
            "--sapling-key-file",
            cli.sapling_key_file.is_some(),
            reads_sapling,
        ),
        (
            "--sprout-key-file",
            cli.sprout_key_file.is_some(),
            reads_sprout,
        ),
    ];
    for (flag, given, read) in supplied {
        if given && !read {
            let hint = if flag == "--sprout-key-file" {
                " A raw Sprout key is recovered with `argos scan-sprout --sprout-key-file <file>`."
            } else {
                ""
            };
            bail!(
                "{flag} is not used by the {name} command, so the key it names would be ignored.{hint}"
            );
        }
    }
    Ok(())
}

/// Refuse `--no-birthday-skip` where nothing is skipped.
///
/// Unlike the scan-tuning flags, this one is a safety control: a user who
/// passes it believes every block is being decrypted, so it must not be
/// accepted by a command that would quietly ignore it.
fn refuse_unconsumed_birthday_skip(cli: &Cli) -> Result<()> {
    if cli.no_birthday_skip && !matches!(cli.command, Commands::ScanSprout { .. }) {
        bail!(
            "--no-birthday-skip is not used by this command: only `argos scan-sprout` skips \
             trial decryption."
        );
    }
    if matches!(cli.command, Commands::ScanSprout { .. }) {
        // The Sprout decrypt floor comes from --birthday alone. These two
        // would otherwise be accepted and ignored, leaving a user who meant
        // to lower the floor believing they had.
        let ignored = if cli.birthday_date.is_some() {
            Some("--birthday-date")
        } else if cli.birthday_auto_detect {
            Some("--birthday-auto-detect")
        } else {
            None
        };
        if let Some(flag) = ignored {
            bail!(
                "{flag} is not used by `argos scan-sprout`. Its walk always starts at block 1; \
                 to lower the block trial decryption starts from, pass --birthday <height>, or \
                 --no-birthday-skip to decrypt every block."
            );
        }
    }
    Ok(())
}

/// Read a legacy wallet file into key material.
///
/// The passphrase is prompted for, never taken as a flag: a flag would
/// land in shell history and in `ps` output for every user on the box
/// (T-S6 in the threat model). We attempt an unencrypted read first so an
/// unencrypted wallet is never asked for a passphrase it does not have.
fn load_wallet_file(path: &Path, network: ZeckNetwork) -> Result<ImportedKeys> {
    let bytes = argos_core::wallet_file::read_wallet_file(path)
        .with_context(|| format!("failed to read wallet file {}", path.display()))?;

    match argos_core::import_wallet_file_for_network(&bytes, None, network) {
        Ok(mut keys) => {
            report_forged_sprout_keys(&mut keys);
            Ok(keys)
        }
        // The parser reports a locked wallet and a wrong passphrase with
        // the same variant. Here it can only mean "locked", because we
        // supplied no passphrase to be wrong. Matched by type, not message
        // text, so rewording the error cannot silently stop the prompt.
        Err(argos_core::ZeckError::WalletFile(
            argos_wallet_import::ImportError::WrongPassphrase,
        )) => {
            eprintln!("This wallet is encrypted.");
            let passphrase = Password::new()
                .with_prompt("Enter the wallet passphrase")
                .allow_empty_password(false)
                .interact()
                .context("failed to read wallet passphrase from terminal")?;
            let passphrase = SecretString::new(passphrase);
            let mut keys =
                argos_core::import_wallet_file_for_network(&bytes, Some(&passphrase), network)
                    .with_context(|| format!("failed to import wallet file {}", path.display()))?;
            report_forged_sprout_keys(&mut keys);
            Ok(keys)
        }
        Err(err) => {
            Err(err).with_context(|| format!("failed to import wallet file {}", path.display()))
        }
    }
}

/// Read a Sapling key file into the same key set a wallet file produces.
///
/// The file is moved into a zeroizing string immediately and never logged.
/// Decoding and deduplication use the shared core routines; line handling is
/// kept here so no ordinary `Vec<String>` ever owns the plaintext keys.
fn load_sapling_key_file(path: &Path, network: ZeckNetwork) -> Result<ImportedKeys> {
    use argos_core::argos_wallet_import::{Provenance, SaplingKey};

    let text = read_secret_text_file(path)?;
    let text = text.as_str()?;
    let mut keys = ImportedKeys::default();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let extsk = argos_core::sapling_key::decode_sapling_spending_key(line, network)
            .with_context(|| format!("line {} of {}", index + 1, path.display()))?;
        let decoded = ImportedKeys {
            sapling: vec![SaplingKey {
                extsk: Secret::new(extsk.to_bytes().to_vec()),
                provenance: Provenance::Standalone,
                created_at: None,
            }],
            ..Default::default()
        };
        argos_core::sapling_key::merge_sapling_keys(&mut keys, decoded);
    }
    if keys.sapling.is_empty() {
        bail!(
            "in {}: no Sapling spending keys found — expected at least one \
             `secret-extended-key-…` line",
            path.display()
        );
    }
    Ok(keys)
}

/// Upper bound for human-entered seed and spending-key files. It also lets us
/// allocate the zeroizing buffer before the first byte arrives, so a partial
/// read or invalid UTF-8 error cannot drop a plaintext `String` allocation.
const MAX_SECRET_TEXT_FILE_BYTES: usize = 1024 * 1024;

struct SecretTextFile(secrecy::zeroize::Zeroizing<Vec<u8>>);

impl SecretTextFile {
    fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.0).context("secret text file is not valid UTF-8")
    }
}

fn read_secret_text_file(path: &Path) -> Result<SecretTextFile> {
    let file = fs::File::open(path)
        .with_context(|| format!("failed to open secret file {}", path.display()))?;
    let mut bytes =
        secrecy::zeroize::Zeroizing::new(Vec::with_capacity(MAX_SECRET_TEXT_FILE_BYTES + 1));
    file.take((MAX_SECRET_TEXT_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("failed to read secret file {}", path.display()))?;
    if bytes.len() > MAX_SECRET_TEXT_FILE_BYTES {
        bail!(
            "secret file {} exceeds the {} byte limit",
            path.display(),
            MAX_SECRET_TEXT_FILE_BYTES
        );
    }
    Ok(SecretTextFile(bytes))
}

/// Drop any Sprout key that does not control its stored address, and say so.
///
/// Enforced at every entry point rather than only where a sweep happens: a
/// key that fails this check would derive a wrong address, find no notes,
/// and give the user no indication why — and if it did somehow match a
/// note, spending with it would build a transaction for someone else's.
fn report_forged_sprout_keys(keys: &mut ImportedKeys) {
    for rejected in argos_core::sprout_recovery::reject_forged_sprout_keys(keys) {
        eprintln!();
        eprintln!("  ⚠ A SPROUT KEY IN THIS FILE IS NOT GENUINE");
        eprintln!("    {rejected}");
        eprintln!();
    }
}

async fn run_reconcile(
    data_dir: &Path,
    network: ZeckNetwork,
    lightwalletd_url: &str,
    confirmation_source: &[String],
    txid: Option<&str>,
    resubmit: bool,
) -> Result<()> {
    let registry = argos_core::service::NetworkOperationGuard::acquire(data_dir, network)?;
    let mut log = registry.open_broadcast_log()?;
    let records = log.records();
    let selected = if let Some(requested) = txid {
        Some(
            records
                .iter()
                .find(|record| {
                    record
                        .prepared
                        .txid
                        .to_string()
                        .eq_ignore_ascii_case(requested)
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "transaction {requested} was not found in the durable network registry"
                    )
                })?
                .prepared
                .txid,
        )
    } else {
        None
    };
    if records.is_empty() {
        println!(
            "No stored transactions in the {} network registry.",
            network.label()
        );
        return Ok(());
    }

    let sources = argos_core::lightwalletd::parse_confirmation_sources(
        &confirmation_source
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )?;
    let mut observer =
        argos_core::lightwalletd::LightwalletdTxObserver::new(lightwalletd_url, &sources)?;
    if resubmit {
        let selected = selected.expect("clap requires --txid with --resubmit");
        let (mut client, _endpoint, info) =
            argos_core::lightwalletd::probe_lightwalletd_endpoints_with_retry(lightwalletd_url)
                .await?;
        argos_core::lightwalletd::validate_lightwalletd_network(network, &info)?;
        let mut submitter = argos_core::broadcast::LightwalletdSubmitter {
            client: &mut client,
        };
        let result = argos_core::reconciliation::retry_unknown_transaction(
            &mut log,
            &mut observer,
            &mut submitter,
            network,
            selected,
            Duration::from_secs(30),
        )
        .await?;
        print_reconciled_transaction(&result);
        return Ok(());
    }

    let results = if let Some(selected) = selected {
        vec![
            argos_core::reconciliation::observe_reconciled_transaction(
                &mut log,
                &mut observer,
                network,
                selected,
            )
            .await?,
        ]
    } else {
        argos_core::reconciliation::observe_all_reconciled_transactions(
            &mut log,
            &mut observer,
            network,
        )
        .await?
    };
    for result in &results {
        print_reconciled_transaction(result);
    }
    Ok(())
}

fn print_reconciled_transaction(result: &argos_core::reconciliation::ReconciledTransaction) {
    println!("  Transaction  {}", result.txid);
    println!("  Status       {:?}", result.status);
    println!("  Fee          {}", format_zec(result.fee_zatoshis));
    println!("  {}", result.detail);
    println!();
}

/// Sweep a transparent-only wallet, with the same guard rails the HD sweep
/// has: a dry run that signs nothing, an explicit confirmation for an
/// irreversible action, and a fee ceiling checked before signing.
#[allow(clippy::too_many_arguments)]
async fn run_transparent_sweep(
    keys: &[argos_core::imported::ImportedTransparentKey],
    data_dir: &Path,
    network: ZeckNetwork,
    lightwalletd_url: &str,
    destination: &str,
    max_fee: Option<u64>,
    dry_run: bool,
    confirm_sweep: bool,
) -> Result<()> {
    // Hold the durable lock through scanning and submission. A prior unknown
    // transaction takes precedence even if the new UTXO scan is empty.
    let registry = argos_core::service::NetworkOperationGuard::acquire(data_dir, network)?;
    let legacy_path =
        argos_core::transparent_recovery::standalone_broadcast_log_path(data_dir, keys, network);
    let mut log = registry.open_broadcast_log_for(&legacy_path)?;
    if let Some(txid) = log.blocking_submission() {
        bail!(
            "transaction {txid} may already have reached the network or was retryably refused; \
             reconcile its durable record before starting another sweep"
        );
    }
    if log.has_unresolved_history() {
        let txid = log
            .records()
            .into_iter()
            .find(|record| record.state == argos_core::TxLifecycleState::NotSubmitted)
            .map(|record| record.prepared.txid.to_string())
            .unwrap_or_else(|| "unknown".to_owned());
        bail!(
            "transaction {txid} has prepared bytes in the durable registry; reconcile or \
             resubmit those exact bytes before starting another sweep"
        );
    }
    // Report before deciding, so a dry run and a real sweep show the user
    // the same numbers.
    let quote = quote_transparent_only(keys, network, lightwalletd_url).await?;
    let report = quote.report();
    print_transparent_report(report);

    if report.total_zatoshis == 0 {
        println!();
        println!("Nothing to sweep.");
        return Ok(());
    }

    let plan = quote
        .plan()
        .ok_or_else(|| anyhow::anyhow!("the quoted transparent sweep has no inputs"))?;
    println!();
    println!("{}", transparent_sweep_review(plan, destination));
    if let Some(cap) = max_fee {
        println!("  Fee ceiling        {}", format_zec(cap));
    }
    println!("All transparent funds above would be swept into a single shielded (Sapling) output.");

    if dry_run {
        println!();
        println!("╔══════════════════════════════════════╗");
        println!("║  DRY RUN — no funds will be moved    ║");
        println!("╚══════════════════════════════════════╝");
        println!();
        println!("Re-run with --confirm-sweep to broadcast.");
        return Ok(());
    }

    if !confirm_sweep {
        bail!(
            "refusing to broadcast without --confirm-sweep. Re-run with --dry-run to preview, \
             or --confirm-sweep to move the funds. This is irreversible."
        );
    }

    let outcome = sweep_transparent_only_from_quote(
        &mut log,
        keys,
        network,
        lightwalletd_url,
        destination,
        Some(transparent_sweep_fee_cap(max_fee, plan)),
        &quote,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("there was nothing to sweep"))?;

    println!();
    println!("━━━ Sweep submission ━━━");
    println!(
        "  Transaction  {}",
        outcome.transaction.txid.as_deref().unwrap_or("unknown")
    );
    println!("  Inputs       {}", outcome.plan.input_count);
    println!("  Fee          {}", format_zec(outcome.plan.fee_zatoshis));
    println!(
        "  Planned output  {}",
        format_zec(outcome.plan.output_zatoshis)
    );
    println!("  Destination  {}", outcome.destination);
    println!();
    if outcome.transaction.status == argos_core::TxLifecycleState::SubmissionUnknown {
        bail!("Transaction {} (fee {}) may already have reached the network; do not retry or discard the source wallet. Reconcile this txid before any further sweep. {}",
            outcome.transaction.txid.as_deref().unwrap_or("unknown"),
            format_zec(outcome.transaction.fee_zatoshis), outcome.transaction.detail);
    }
    if outcome.transaction.status == argos_core::TxLifecycleState::Rejected {
        bail!(
            "Transaction {} was rejected: {}",
            outcome.transaction.txid.as_deref().unwrap_or("unknown"),
            outcome.transaction.detail
        );
    }
    if matches!(
        outcome.disposition,
        argos_core::broadcast::SubmissionDisposition::RetryableRejection { .. }
    ) {
        bail!("Transaction {} was retryably refused; reconcile the stored transaction before retrying. Do not submit another sweep leg.", outcome.transaction.txid.as_deref().unwrap_or("unknown"));
    }
    // Mempool acceptance is not confirmation, and a recovery user reading
    // "broadcast" as "done" may delete the wallet file that still holds the
    // only copy of these keys.
    println!(
        "The network accepted this transaction into its mempool. That is not the same as \
         it being mined. Check the transaction id above in a block explorer before treating \
         the funds as moved, and keep the original wallet file until you have."
    );

    Ok(())
}

fn transparent_sweep_review(plan: &TransparentSweepPlan, destination: &str) -> String {
    format!(
        "  Inputs             {}\n  Gross              {}\n  Fee                {}\n  Net to destination {}\n  Destination        {}",
        plan.input_count,
        format_zec(plan.total_input_zatoshis),
        format_zec(plan.fee_zatoshis),
        format_zec(plan.output_zatoshis),
        destination,
    )
}

fn transparent_sweep_fee_cap(max_fee: Option<u64>, plan: &TransparentSweepPlan) -> u64 {
    max_fee.unwrap_or(plan.fee_zatoshis)
}

/// Whether this wallet must go down the transparent-only path.
///
/// Only when it has *no* Sapling keys. A wallet with Sapling keys can be
/// given a wallet-database account, and that account carries the
/// transparent keys as standalone receivers — so the shielded scan covers
/// both pools in one pass. Routing such a wallet here instead would report
/// its transparent balance while silently ignoring its Sapling notes.
fn is_transparent_only(keys: &ImportedKeys) -> bool {
    // One shared classifier: this predicate, the GUI's, and core's refusal
    // were three different definitions that had to agree and did not.
    argos_core::key_source::classify_recovery_route(keys)
        == argos_core::key_source::RecoveryRoute::TransparentOnly
}

/// Warn — unmissably — about every pool this recovery will not cover.
///
/// This is the project's partial-recovery rule applied to whole pools:
/// covering what we can must never imply we covered everything. A user who
/// reads "0.5 ZEC recovered" without knowing a pool was never looked at has
/// been actively misled about where their money is — and may discard the
/// wallet file holding the only copy of those keys.
///
/// `covers_shielded` distinguishes the two import paths: the transparent-only
/// path reaches exactly one pool, while the imported-account path scans
/// Sapling and transparent together and leaves only Sprout behind.
fn warn_about_uncovered_pools(keys: &ImportedKeys, covers_shielded: bool) {
    let uncovered_sapling = if covers_shielded {
        0
    } else {
        keys.sapling.len()
    };
    warn_about_partial_import(keys);
    if uncovered_sapling == 0 && keys.sprout.is_empty() {
        return;
    }

    eprintln!();
    if covers_shielded {
        eprintln!("  ⚠ SPROUT FUNDS ARE NOT COVERED");
    } else {
        eprintln!("  ⚠ THIS COVERS TRANSPARENT FUNDS ONLY");
    }
    if uncovered_sapling > 0 {
        eprintln!(
            "    {uncovered_sapling} Sapling key(s) in this wallet are NOT scanned or swept here."
        );
    }
    if !keys.sprout.is_empty() {
        eprintln!(
            "    {} Sprout key(s) in this wallet are NOT scanned or swept here.",
            keys.sprout.len()
        );
        eprintln!("    Sprout is recovered separately — run `inspect-wallet` to see what");
        eprintln!("    this file holds for them, and what recovering them would cost.");
    }
    eprintln!("    Any balance reported below excludes those pools entirely.");
    eprintln!("    Keep the original wallet file: those keys exist only there.");
    eprintln!();
}

/// Repeat, before any balance appears, that the import itself may be
/// incomplete. `inspect-wallet` says it once; a user who goes straight to
/// `scan` would otherwise read a total with nothing attached to it.
fn warn_about_partial_import(keys: &ImportedKeys) {
    if !keys.coverage().may_hide_funds() {
        return;
    }
    if let Some(notice) = keys.coverage_notice() {
        eprintln!();
        eprintln!("  ⚠ THIS WALLET FILE WAS ONLY PARTLY RECOVERED");
        eprintln!("    {notice}");
        eprintln!("    Run `inspect-wallet` to see which records were skipped.");
        eprintln!();
    }
}

/// Whether a sweep may broadcast: `--dry-run` and `--confirm-sweep`.
struct SweepGate {
    dry_run: bool,
    confirm_sweep: bool,
}

/// Recover Sprout notes from a wallet file and move them to Sapling.
///
/// Thin by design: address parsing, branch-id selection, proving and
/// broadcast all live in `argos-core`, because the GUI needs exactly the
/// same sequence and a second copy here would drift from it.
#[allow(clippy::too_many_arguments)]
async fn sweep_sprout(
    keys: &ImportedKeys,
    network: ZeckNetwork,
    data_dir: &Path,
    peers: &[String],
    lightwalletd_url: &str,
    confirmation_source: &[String],
    destination: &str,
    sprout_params: Option<PathBuf>,
    gate: SweepGate,
) -> Result<()> {
    print_sprout_nu7_warning(network);
    let SweepGate {
        dry_run,
        confirm_sweep,
    } = gate;
    let recovered = recover_with_scan(keys, network, data_dir, ScanEvidence::Verify(peers)).await;
    let spending_keys = wallet_sprout_keys(keys);
    let journal = argos_core::sprout_sweep::SweepJournal::for_keys(
        data_dir,
        spending_keys.as_slice(),
        network,
    );
    let outpoints = recovered
        .notes
        .iter()
        .map(|note| note.outpoint)
        .collect::<Vec<_>>();
    let snapshot = journal.load_scoped_snapshot(&outpoints)?;
    let inventory = argos_core::sprout_sweep::classify_sprout_notes(&recovered.notes, &snapshot);
    let preview_plan = sprout_preview_plan(&inventory)?;
    // stdout, beside the plan: `> plan.txt` must keep the reason the total
    // is smaller than the wallet's history.
    print_sprout_accounting(keys, &recovered, false, "argos inspect-wallet --show-spent");
    print_sprout_lifecycle_entries(&snapshot);
    if sprout_nothing_left(&recovered, &inventory, &snapshot, true) {
        println!("Nothing is left to sweep: every Sprout note this file records was spent by");
        println!("the wallet itself or is worth less than the fee to move it.");
        println!("To check that against the chain: argos scan-sprout --wallet-file <this file>");
        println!();
        print_sprout_scan_cost_warning(network);
        return Ok(());
    }

    if recovered.notes.is_empty() && snapshot.entries().next().is_none() {
        eprintln!("No spendable Sprout notes could be recovered from this wallet file.");
        if !recovered.issues.is_empty() {
            eprintln!("Why:");
            for issue in recovered.issues.iter().take(10) {
                eprintln!("  - {issue}");
            }
        }
        eprintln!();
        print_sprout_scan_cost_warning(network);
        anyhow::bail!("nothing to sweep from this file");
    }

    let no_ready_action = sprout_no_ready_action(
        preview_plan.is_some(),
        snapshot.entries().map(|entry| entry.state),
    );
    if no_ready_action == Some(SproutNoReadyAction::RecoverOrRescan) {
        println!("No Sprout note is ready for a new transaction.");
        if let Some(guidance) =
            sprout_lifecycle_status_guidance(snapshot.entries().map(|entry| entry.state))
        {
            for line in wrap_text(guidance, 76) {
                println!("  {line}");
            }
        }
        println!();
        return Ok(());
    }

    if let Some(plan) = preview_plan {
        println!();
        println!("\u{2501}\u{2501}\u{2501} Sprout sweep \u{2501}\u{2501}\u{2501}");
        println!("  Notes              {}", plan.notes);
        println!("  Gross              {}", format_zec(plan.gross_zatoshis));
        println!("  Fee                {}", format_zec(plan.fee_zatoshis));
        println!("  Net to destination {}", format_zec(plan.net_zatoshis));
        println!("  Destination        {destination}");
        println!();
    } else {
        debug_assert_eq!(no_ready_action, Some(SproutNoReadyAction::Reconcile));
        println!("No Sprout note is ready for a new transaction; lifecycle journal entries");
        println!("will be reconciled before any proving work.");
        println!();
    }
    // Said before the confirmation, not after the broadcast: someone who
    // pastes a Unified Address expects the funds in its best pool, and for
    // Sprout that is never Orchard.
    for line in wrap_text(argos_core::sprout_sweep::SPROUT_LANDS_IN_SAPLING, 76) {
        println!("  {line}");
    }
    println!();
    // Before the confirmation, where it changes the decision: this is the
    // one limit that costs proving time rather than showing up in a count.
    for line in wrap_text(&recovered.spent_status(), 76) {
        println!("  {line}");
    }
    println!();

    if dry_run {
        println!("Dry run: nothing was built or broadcast.");
        if snapshot
            .entries()
            .any(|entry| entry.state == argos_core::TxLifecycleState::SubmissionUnknown)
        {
            anyhow::bail!("a Sprout submission remains unknown; later work stays stopped");
        }
        return Ok(());
    }
    if !confirm_sweep {
        anyhow::bail!(
            "this moves funds irreversibly. Re-run with --confirm-sweep to broadcast, \
             or --dry-run to preview."
        );
    }

    let params_path = sprout_params.unwrap_or_else(argos_core::sprout_sweep::default_params_path);
    let confirmation_sources = argos_core::lightwalletd::parse_confirmation_sources(
        &confirmation_source
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )?;
    eprintln!(
        "Each broadcast is recorded in {}, so an interrupted sweep resumes without \
         proving any note twice.",
        journal.path().display()
    );
    let outcome = argos_core::sprout_sweep::sweep_sprout_notes(
        &recovered.notes,
        network,
        lightwalletd_url,
        destination,
        &params_path,
        argos_core::sprout_sweep::SweepOptions {
            source: argos_core::sprout_sweep::NoteSource::WalletFile,
            journal: &journal,
            confirmation_sources: &confirmation_sources,
        },
        |msg| eprintln!("  {msg}"),
    )
    .await?;

    println!();
    print_sprout_transactions(&outcome);
    print_sprout_nu7_broadcast_warning(network, &outcome);
    report_sprout_skips_and_errors(&outcome);
    if outcome.fresh_all_mined {
        println!(
            "Canonically mined {} from Sprout into Sapling.",
            format_zec(outcome.mined_zatoshis)
        );
    }
    if let Some(pool_line) = sprout_post_execution_pool_line(&outcome) {
        println!();
        println!("{pool_line}");
    }
    // Non-zero, so a script cannot read a sweep that stopped partway as done.
    if outcome.error.is_some() {
        bail!("the Sprout sweep did not finish; see above");
    }
    Ok(())
}

fn sprout_post_execution_pool_line(
    outcome: &argos_core::sprout_sweep::SproutSweepOutcome,
) -> Option<&'static str> {
    (!outcome.transactions.is_empty()).then_some(
        "Sprout recovery transactions move value into Sapling. Use the lifecycle rows above to verify each transaction before moving those funds again.",
    )
}

/// Gather the spending keys a Sprout scan should look for.
///
/// Either from a key file or from a wallet whose own note data was missing.
/// Both are accepted at once, because a user may hold a `wallet.dat` *and*
/// a paper key for an address that wallet never rescanned.
/// The Sprout keys a scan covers.
struct SecretSproutKeys(Vec<[u8; 32]>);

impl SecretSproutKeys {
    fn new(keys: Vec<[u8; 32]>) -> Self {
        Self(keys)
    }

    fn as_slice(&self) -> &[[u8; 32]] {
        &self.0
    }
}

impl Drop for SecretSproutKeys {
    fn drop(&mut self) {
        secrecy::zeroize::Zeroize::zeroize(&mut self.0);
    }
}

struct SproutScanKeys {
    /// Every key, deduplicated: what the scan decrypts for.
    all: SecretSproutKeys,
    /// Those that came from `--sprout-key-file`. They carry no creation
    /// time, so the skip decision must see them apart from the wallet's own.
    from_key_file: SecretSproutKeys,
}

fn collect_sprout_scan_keys(
    key_file: Option<&Path>,
    wallet: Option<&ImportedKeys>,
    network: ZeckNetwork,
) -> Result<SproutScanKeys> {
    use secrecy::ExposeSecret;

    let mut from_file_values = secrecy::zeroize::Zeroizing::new(Vec::<[u8; 32]>::new());

    if let Some(path) = key_file {
        let text = read_secret_text_file(path)?;
        let text = text.as_str()?;
        from_file_values.reserve_exact(text.lines().count());
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            // Blank lines and `#` comments, so a user can annotate which key
            // came from which backup without the file being rejected.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let key = argos_core::sprout_key::decode_sprout_spending_key(line, network)
                .with_context(|| format!("line {} of {}", index + 1, path.display()))?;
            from_file_values.push(key);
        }
    }

    let from_key_file = SecretSproutKeys::new(from_file_values.to_vec());
    // Allocate the combined set once. Reallocating a Vec after it contains
    // keys can strand the old allocation without a chance to wipe it.
    let wallet_len = wallet.map_or(0, |wallet| wallet.sprout.len());
    let mut keys = secrecy::zeroize::Zeroizing::new(Vec::<[u8; 32]>::with_capacity(
        from_file_values.len() + wallet_len,
    ));
    keys.extend_from_slice(&from_file_values);
    if let Some(wallet) = wallet {
        keys.extend(wallet.sprout.iter().map(|key| *key.a_sk.expose_secret()));
    }

    // A wallet listing the same address twice, or a key file repeating one,
    // would otherwise trial-decrypt every ciphertext twice for no gain.
    keys.sort_unstable();
    keys.dedup();

    if keys.is_empty() {
        anyhow::bail!(
            "no Sprout spending keys to scan for. Pass --sprout-key-file with one \
             SK…/ST… key per line, or --wallet-file for a wallet holding Sprout keys."
        );
    }
    Ok(SproutScanKeys {
        all: SecretSproutKeys::new(std::mem::take(&mut *keys)),
        from_key_file,
    })
}

/// Where the Sprout scan starts trial-decrypting, and the line saying why.
///
/// The skip is derived only from the wallet's own dated Sprout keys; every
/// key-file key is passed as an extra so that an undated one rules it out.
fn sprout_scan_plan(
    wallet: Option<&ImportedKeys>,
    key_file_keys: &[[u8; 32]],
    network: ZeckNetwork,
    birthday: Option<u32>,
    no_birthday_skip: bool,
    now: i64,
) -> argos_core::SproutDecryptPlan {
    let empty = ImportedKeys::default();
    // No Sapling keys are added here: --sprout-key-file keys are passed as
    // Sprout extras, which only the skip reads.
    let dated = argos_core::wallet_file_birthday_from_metadata(
        wallet.unwrap_or(&empty),
        key_file_keys,
        network,
        0,
        now,
    );
    argos_core::plan_sprout_decrypt(
        dated.sprout_skip_height,
        &dated.sprout_skip_reason,
        birthday,
        no_birthday_skip,
    )
}

/// Learn a block near the tip from lightwalletd, for the scan to match.
///
/// Best-effort: the Sprout scan does not otherwise need lightwalletd, so a
/// server that cannot be reached does not stop it. It does weaken it, and
/// the user is told how.
async fn sprout_tip_anchor(
    network: ZeckNetwork,
    lightwalletd_url: &str,
) -> (
    Option<argos_core::sprout_scan_run::TipAnchor>,
    Option<String>,
) {
    match argos_core::sprout_scan_run::independent_tip_anchor(network, lightwalletd_url).await {
        Ok(anchor) => {
            eprintln!(
                "The scan will run to the chain tip, and must pass block {} as lightwalletd \
                 reports it.",
                anchor.height
            );
            (Some(anchor), None)
        }
        Err(err) => {
            let warning = argos_core::sprout_scan_run::unconfirmed_tip_warning(
                network.into(),
                &err.to_string(),
            );
            eprintln!("  ⚠ {warning}");
            (None, Some(warning))
        }
    }
}

fn apply_sprout_tip_warning(
    outcome: &mut argos_core::sprout_sweep::SproutSweepOutcome,
    warning: Option<String>,
) {
    if let Some(warning) = warning {
        outcome.fresh_all_mined = false;
        outcome.warnings.insert(0, warning);
    }
}

fn apply_checkpoint_cleanup_error(
    outcome: &mut argos_core::sprout_sweep::SproutSweepOutcome,
    err: &dyn std::fmt::Display,
) {
    outcome.fresh_all_mined = false;
    outcome
        .warnings
        .push(format!("Checkpoint cleanup failed: {err}"));
}

/// Scan the chain for a set of Sprout keys, then optionally sweep what it finds.
#[allow(clippy::too_many_arguments)]
async fn scan_sprout(
    keys: &[[u8; 32]],
    network: ZeckNetwork,
    lightwalletd_url: &str,
    confirmation_source: &[String],
    data_dir: &Path,
    peers: &[String],
    destination: Option<&str>,
    sprout_params: Option<PathBuf>,
    confirm_sweep: bool,
    decrypt_from: Option<u32>,
) -> Result<()> {
    print_sprout_nu7_warning(network);
    let p2p_network: P2pNetwork = network.into();

    // The destination is validated before the scan, not after. Discovering
    // that an address has no Sapling receiver at the end of a six-hour scan
    // would be the worst possible time to find out.
    if let Some(dest) = destination {
        argos_core::sprout_sweep::parse_sapling_destination(dest, network)?;
        // The sweep is broadcast through lightwalletd, after the scan. A
        // server address that cannot work is otherwise found out only then,
        // hours in — as a user who passed `--lightwalletd-url nonono` would
        // have.
        argos_core::lightwalletd::validated_lightwalletd_endpoints(lightwalletd_url).map_err(
            |err| {
                anyhow::anyhow!(
                    "--destination sweeps through --lightwalletd-url once the scan finishes, \
                     and that server address cannot work ({err}). Fix it before scanning, or \
                     drop --destination to scan and report only."
                )
            },
        )?;
    }

    println!();
    for key in keys {
        let addr = argos_core::sprout_key::encode_sprout_address(
            &argos_core::sprout::SproutPaymentAddress::from_spending_key(key),
            network,
        );
        println!("  scanning for {addr}");
    }
    println!();
    print_sprout_scan_cost_warning(network);

    let (tip_anchor, tip_warning) = sprout_tip_anchor(network, lightwalletd_url).await;
    let tip_height = tip_anchor.as_ref().map(|anchor| anchor.height);

    let checkpoint = argos_core::sprout_scan_run::checkpoint_path(data_dir, keys);
    let mut journal = argos_core::sprout_sweep::SweepJournal::for_keys(data_dir, keys, network);
    if let Some(recovered) = argos_core::sprout_sweep::resume_interrupted_scan_checkpoint_cleanup(
        &checkpoint,
        &journal,
        network,
    )? {
        match recovered {
            argos_core::sprout_sweep::ScanCheckpointCleanup::Removed
            | argos_core::sprout_sweep::ScanCheckpointCleanup::AlreadyAbsent => {
                println!(
                    "Completed an interrupted cleanup of the prior Sprout scan checkpoint. Run the scan again to create a fresh source."
                );
                return Ok(());
            }
            argos_core::sprout_sweep::ScanCheckpointCleanup::Retained(reason) => {
                anyhow::bail!("interrupted checkpoint cleanup was retained: {reason}")
            }
        }
    }
    // Worded for what exists: nothing is written until the first
    // checkpoint, and a scan that has not started must not look saved.
    eprintln!(
        "Progress will be saved to {} (first written after {} blocks).",
        checkpoint.display(),
        argos_core::sprout_scan_run::CHECKPOINT_EVERY
    );
    eprintln!("Interrupt with Ctrl-C at any time and re-run to resume.");
    eprintln!();

    let started = std::time::Instant::now();
    let mut last_report = std::time::Instant::now();
    // A resume that would change which blocks were decrypted fails here
    // with the core's own explanation, which already names the way out.
    let result = argos_core::sprout_scan_run::run_sprout_scan_with_decrypt_from(
        keys,
        p2p_network,
        peers,
        tip_anchor,
        &checkpoint,
        decrypt_from,
        |tick| {
            // A wait for a peer is printed every time it is announced, not
            // rate-limited with the rest: the core already spaces these out,
            // and they arrive precisely when nothing else is being printed,
            // which is when silence would read as a hang.
            if let Some(wait) = tick.peer_wait {
                eprintln!("  {wait}");
                return;
            }
            // Rate-limited: a tick per batch would scroll a six-hour scan
            // off the screen and tell the user nothing extra.
            if last_report.elapsed().as_secs() >= 5 {
                last_report = std::time::Instant::now();
                let pct = (f64::from(tick.height) / f64::from(tick.target.max(1))) * 100.0;
                eprintln!(
                    "  {:>7}/{} ({pct:.1}%)  {} JoinSplits  {} note(s)  {}",
                    tick.height,
                    tick.target,
                    tick.joinsplits_seen,
                    tick.notes_found,
                    fmt_elapsed(started.elapsed()),
                );
            }
        },
    )
    .await?;

    println!();
    println!("━━━ Sprout scan complete ━━━");
    println!("  Blocks scanned    {}", result.progress.blocks_scanned);
    // The bound actually used, which after a resume is the checkpoint's.
    match result.decrypt_from_height {
        Some(height) => println!("  Decrypted from    block {height}"),
        None => println!("  Decrypted from    block 1 (every block)"),
    }
    // The plan printed before the scan promised a skip; say why it did not
    // happen rather than leave that standing.
    if let Some(line) = argos_core::sprout_scan_run::dropped_bound_line(decrypt_from, tip_height) {
        println!("  {line}");
    }
    println!("  JoinSplits seen   {}", result.progress.joinsplits_seen);
    println!("  Notes found       {}", result.notes.len());
    println!("  Already spent     {}", result.spent_notes);
    println!("  Total             {}", format_zec(result.total_value()));
    println!();

    let outpoints = result
        .notes
        .iter()
        .map(|note| note.outpoint)
        .collect::<Vec<_>>();
    let snapshot = journal.load_scoped_snapshot(&outpoints)?;
    let inventory = argos_core::sprout_sweep::classify_sprout_notes(&result.notes, &snapshot);
    let preview_plan = sprout_preview_plan(&inventory)?;
    print_sprout_lifecycle_entries(&snapshot);

    if result.notes.is_empty() && snapshot.entries().next().is_none() {
        println!("No unspent Sprout notes were found for these keys.");
        return Ok(());
    }

    let no_ready_action = sprout_no_ready_action(
        preview_plan.is_some(),
        snapshot.entries().map(|entry| entry.state),
    );
    if no_ready_action == Some(SproutNoReadyAction::RecoverOrRescan) {
        println!("No Sprout note is ready for a new transaction.");
        if let Some(guidance) =
            sprout_lifecycle_status_guidance(snapshot.entries().map(|entry| entry.state))
        {
            for line in wrap_text(guidance, 76) {
                println!("  {line}");
            }
        }
        println!();
        return Ok(());
    }

    let Some(destination) = destination else {
        for line in sprout_scan_followup_guidance(no_ready_action, false) {
            println!("{line}");
        }
        return Ok(());
    };
    if !confirm_sweep {
        for line in sprout_scan_followup_guidance(no_ready_action, true) {
            println!("{line}");
        }
        if snapshot
            .entries()
            .any(|entry| entry.state == argos_core::TxLifecycleState::SubmissionUnknown)
        {
            anyhow::bail!("a Sprout submission remains unknown; later work stays stopped");
        }
        return Ok(());
    }

    let params_path = sprout_params.unwrap_or_else(argos_core::sprout_sweep::default_params_path);
    let confirmation_sources = argos_core::lightwalletd::parse_confirmation_sources(
        &confirmation_source
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    )?;
    let checkpoint_authority = argos_core::sprout_sweep::prepare_scan_checkpoint_authority(
        &checkpoint,
        result.checkpoint_generation.as_ref().ok_or_else(|| {
            anyhow::anyhow!("the completed scan did not return a checkpoint generation")
        })?,
        &mut journal,
        &result.notes,
        network,
    )?;
    let mut outcome = argos_core::sprout_sweep::sweep_sprout_notes(
        &result.notes,
        network,
        lightwalletd_url,
        destination,
        &params_path,
        argos_core::sprout_sweep::SweepOptions {
            source: argos_core::sprout_sweep::NoteSource::Scan,
            journal: &journal,
            confirmation_sources: &confirmation_sources,
        },
        |msg| eprintln!("  {msg}"),
    )
    .await?;
    apply_sprout_tip_warning(&mut outcome, tip_warning);

    let checkpoint_cleanup = argos_core::sprout_sweep::finalize_scan_checkpoint(
        &checkpoint_authority,
        &journal,
        network,
        outcome.fresh_all_mined,
    );
    match checkpoint_cleanup {
        Ok(argos_core::sprout_sweep::ScanCheckpointCleanup::Removed)
        | Ok(argos_core::sprout_sweep::ScanCheckpointCleanup::AlreadyAbsent) => {
            println!("The fully mined scan checkpoint was removed.");
        }
        Ok(argos_core::sprout_sweep::ScanCheckpointCleanup::Retained(reason)) => {
            outcome.fresh_all_mined = false;
            outcome
                .warnings
                .push(format!("Checkpoint retained: {reason}."));
        }
        Err(err) => {
            apply_checkpoint_cleanup_error(&mut outcome, &err);
        }
    }

    print_sprout_transactions(&outcome);
    print_sprout_nu7_broadcast_warning(network, &outcome);
    report_sprout_skips_and_errors(&outcome);
    if outcome.fresh_all_mined {
        println!(
            "Canonically mined {} from Sprout into Sapling.",
            format_zec(outcome.mined_zatoshis)
        );
    }
    if outcome.error.is_some() {
        bail!("the Sprout sweep did not finish; see above");
    }
    Ok(())
}

/// Why the Sprout total is what it is: notes the wallet spent, dust,
/// unconfirmed spends, and unreadable transactions. Shared by inspect-wallet
/// and sweep-sprout so the two cannot describe one file differently.
fn print_sprout_accounting(
    keys: &ImportedKeys,
    recovered: &argos_core::sprout_recovery::SproutRecovery,
    show_spent: bool,
    list_with: &str,
) {
    for line in recovered.accounting_lines() {
        for wrapped in wrap_text(&line, 76) {
            println!("  {wrapped}");
        }
    }
    if !recovered.spent.is_empty() {
        if show_spent {
            for n in &recovered.spent {
                let by = match &n.spent_in {
                    SpentEvidence::Wallet { txid } => format!("spent in {}", display_txid(txid)),
                    SpentEvidence::Chain {
                        txid: Some(txid), ..
                    } => format!("spent on chain in {}", display_txid(txid)),
                    SpentEvidence::Chain {
                        scanned_to,
                        txid: None,
                    } => format!("spent on chain (scan to height {scanned_to})"),
                };
                println!(
                    "    {}:{}:{}  {}  {by}",
                    display_txid(&n.outpoint.txid),
                    n.outpoint.js_index,
                    n.outpoint.output_index,
                    format_zec(n.value),
                );
            }
        } else {
            println!("  List them with `{list_with}`.");
        }
    }
    // Every note the total leaves out can be found again by outpoint, not
    // only the spent ones.
    if show_spent {
        for (what, outpoints) in [
            ("worth less than the fee", &recovered.dust),
            ("with an unconfirmed spend", &recovered.unconfirmed_spends),
        ] {
            for o in outpoints {
                println!(
                    "    {}:{}:{}  {what}",
                    display_txid(&o.txid),
                    o.js_index,
                    o.output_index
                );
            }
        }
    }
    if let Some(warning) = argos_core::sprout_recovery::unreadable_transactions_warning(keys) {
        for line in wrap_text(&warning, 76) {
            println!("  {line}");
        }
    }
    println!();
}

/// Recover the wallet file's Sprout notes, letting a full-block scan of the
/// same keys — if one has run in this data directory — settle every spend it
/// saw on chain. The scan is optional; a checkpoint that cannot be used is
/// reported and the file's own record stands.
enum ScanEvidence<'a> {
    Offline,
    Verify(&'a [String]),
}

async fn recover_with_scan(
    keys: &ImportedKeys,
    network: ZeckNetwork,
    data_dir: &Path,
    evidence: ScanEvidence<'_>,
) -> argos_core::sprout_recovery::SproutRecovery {
    let spending_keys = wallet_sprout_keys(keys);
    let (chain, notice) = match evidence {
        ScanEvidence::Offline => (
            None,
            argos_core::sprout_scan_run::wallet_scan_notice_offline(
                data_dir,
                network.into(),
                spending_keys.as_slice(),
            ),
        ),
        ScanEvidence::Verify(peers) => {
            argos_core::sprout_scan_run::chain_spends_for_wallet(
                data_dir,
                network.into(),
                spending_keys.as_slice(),
                peers,
            )
            .await
        }
    };
    let mut recovered = argos_core::sprout_recovery::recover_spendable_sprout_notes_with_chain(
        keys,
        chain.as_deref(),
    );
    recovered.chain_notice = notice;
    recovered
}

/// The wallet file's Sprout spending keys, in the form the scan checkpoint
/// and the sweep journal are keyed by.
fn wallet_sprout_keys(keys: &ImportedKeys) -> SecretSproutKeys {
    use secrecy::ExposeSecret;
    let mut spending_keys = Vec::with_capacity(keys.sprout.len());
    spending_keys.extend(keys.sprout.iter().map(|k| *k.a_sk.expose_secret()));
    SecretSproutKeys::new(spending_keys)
}

/// A txid as explorers show it: byte-reversed hex.
fn display_txid(txid: &[u8; 32]) -> String {
    txid.iter().rev().map(|b| format!("{b:02x}")).collect()
}

fn sprout_lifecycle_amount(value_zatoshis: Option<u64>) -> String {
    value_zatoshis.map_or_else(|| "amount unknown".to_owned(), format_zec)
}

const SPROUT_KEEP_SOURCE_WARNING: &str =
    "Keep the original wallet or Sprout key and the scan checkpoint. Broadcast is not confirmation.";

fn lifecycle_snapshot_requires_source(
    mut states: impl Iterator<Item = argos_core::TxLifecycleState>,
) -> bool {
    states.next().is_some()
}

fn journal_states_allow_nothing_left(
    states: impl Iterator<Item = argos_core::TxLifecycleState>,
) -> bool {
    !lifecycle_snapshot_requires_source(states)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SproutNoReadyAction {
    Reconcile,
    RecoverOrRescan,
}

fn sprout_no_ready_action(
    has_ready_notes: bool,
    states: impl Iterator<Item = argos_core::TxLifecycleState>,
) -> Option<SproutNoReadyAction> {
    if has_ready_notes {
        return None;
    }
    let mut saw_lifecycle = false;
    let mut saw_reconcilable = false;
    for state in states {
        saw_lifecycle = true;
        saw_reconcilable |= matches!(
            state,
            argos_core::TxLifecycleState::NotSubmitted
                | argos_core::TxLifecycleState::SubmissionUnknown
                | argos_core::TxLifecycleState::Pending
                | argos_core::TxLifecycleState::Mined
        );
    }
    saw_lifecycle.then_some(if saw_reconcilable {
        SproutNoReadyAction::Reconcile
    } else {
        SproutNoReadyAction::RecoverOrRescan
    })
}

fn sprout_scan_followup_guidance(
    no_ready_action: Option<SproutNoReadyAction>,
    destination_present: bool,
) -> [&'static str; 2] {
    match (no_ready_action, destination_present) {
        (Some(SproutNoReadyAction::Reconcile), false) => [
            "Re-run with --destination <zs1…> --confirm-sweep to reconcile the existing journal.",
            "Reconciliation may exact-byte retry saved transaction bytes; it does not create a fresh transaction or run Sprout proving when no note is ready.",
        ],
        (Some(SproutNoReadyAction::Reconcile), true) => [
            "Re-run with --confirm-sweep to reconcile the existing journal.",
            "Reconciliation may exact-byte retry saved transaction bytes; it does not create a fresh transaction or run Sprout proving when no note is ready.",
        ],
        (Some(SproutNoReadyAction::RecoverOrRescan), _) => [
            "Recover or rescan the source before reviewing a new sweep plan.",
            SPROUT_KEEP_SOURCE_WARNING,
        ],
        (None, false) => [
            "Re-run with --destination <zs1…> --confirm-sweep to move these funds.",
            "The scan resumes from its saved progress — it will not download again.",
        ],
        (None, true) => [
            "Re-run with --confirm-sweep to broadcast the sweep.",
            "The scan resumes from its saved progress — it will not download again.",
        ],
    }
}

fn sprout_lifecycle_status_guidance(
    states: impl Iterator<Item = argos_core::TxLifecycleState>,
) -> Option<&'static str> {
    match sprout_no_ready_action(false, states)? {
        SproutNoReadyAction::Reconcile => Some(
            "The lifecycle rows above are the current status for this key set. Keep the original \
             wallet or Sprout key and the scan checkpoint while those transactions are reconciled.",
        ),
        SproutNoReadyAction::RecoverOrRescan => Some(
            "Keep the original wallet or Sprout key and the scan checkpoint. Recover or rescan the \
             source before reviewing a new sweep plan.",
        ),
    }
}

fn sprout_nothing_left(
    recovered: &argos_core::sprout_recovery::SproutRecovery,
    inventory: &argos_core::sprout_sweep::SproutSweepInventory<'_>,
    snapshot: &argos_core::sprout_sweep::SproutJournalSnapshot,
    journal_read: bool,
) -> bool {
    journal_read
        && journal_states_allow_nothing_left(snapshot.entries().map(|entry| entry.state))
        && recovered.nothing_left_to_sweep(inventory)
}

fn sprout_preview_plan(
    inventory: &argos_core::sprout_sweep::SproutSweepInventory<'_>,
) -> argos_core::ZeckResult<Option<argos_core::sprout_sweep::SproutSweepPlan>> {
    argos_core::sprout_sweep::plan_sweep_candidates(&inventory.ready)
}

fn print_sprout_lifecycle_entries(snapshot: &argos_core::sprout_sweep::SproutJournalSnapshot) {
    let retain_source =
        lifecycle_snapshot_requires_source(snapshot.entries().map(|entry| entry.state));
    for entry in snapshot.entries() {
        let txid = entry.txid();
        let amount = sprout_lifecycle_amount(entry.value_zatoshis);
        match entry.state {
            argos_core::TxLifecycleState::Pending => {
                println!("  broadcast/pending {amount} — {txid}");
            }
            argos_core::TxLifecycleState::NotSubmitted
            | argos_core::TxLifecycleState::SubmissionUnknown => {
                println!("  submission status unknown {amount} — {txid}");
            }
            argos_core::TxLifecycleState::Mined => {
                // A journal snapshot is historical evidence. Only an active
                // reconciliation can make this observation fresh enough to
                // release the source material.
                if let Some(height) = entry
                    .observation
                    .as_ref()
                    .filter(|observation| observation.has_canonical_mined_evidence())
                    .and_then(|observation| observation.mined_height)
                {
                    println!("  mined at height {height} {amount} — {txid}");
                } else {
                    println!("  submission status unknown {amount} — {txid}");
                }
            }
            argos_core::TxLifecycleState::Expired => {
                println!("  expired; ready for a new plan {amount} — {txid}");
            }
            argos_core::TxLifecycleState::Rejected => {
                println!("  rejected; value not moved {amount} — {txid}");
            }
        }
    }
    if retain_source {
        println!("{SPROUT_KEEP_SOURCE_WARNING}");
    }
}

fn print_sprout_transactions(outcome: &argos_core::sprout_sweep::SproutSweepOutcome) {
    let mut retain_source = !outcome.fresh_all_mined
        || !outcome.skipped.is_empty()
        || !outcome.rejected.is_empty()
        || outcome.error.is_some();
    for transaction in &outcome.transactions {
        let amount = sprout_lifecycle_amount(transaction.value_zatoshis);
        match transaction.state {
            argos_core::TxLifecycleState::Pending => {
                retain_source = true;
                println!("  broadcast/pending {amount} — {}", transaction.txid);
            }
            argos_core::TxLifecycleState::NotSubmitted
            | argos_core::TxLifecycleState::SubmissionUnknown => {
                retain_source = true;
                println!(
                    "  submission status unknown {amount} — {}",
                    transaction.txid
                );
            }
            argos_core::TxLifecycleState::Mined => {
                if let Some(height) = transaction.mined_height {
                    println!("  mined at height {height} {amount} — {}", transaction.txid);
                } else {
                    retain_source = true;
                    println!(
                        "  submission status unknown {amount} — {}",
                        transaction.txid
                    );
                }
            }
            argos_core::TxLifecycleState::Expired => println!(
                "  expired; ready for a new plan {amount} — {}",
                transaction.txid
            ),
            argos_core::TxLifecycleState::Rejected => println!(
                "  rejected; value not moved {amount} — {}",
                transaction.txid
            ),
        }
    }
    if retain_source {
        println!("{SPROUT_KEEP_SOURCE_WARNING}");
    }
}

/// Print notes that did not move, and any partial failure.
///
/// Both were previously dropped on the floor. A user seeing a smaller total
/// than `inspect-wallet` quoted needs to know which notes stayed behind, and
/// a user whose sweep stopped partway needs the txids of what already went —
/// those funds have moved and are not coming back.
fn report_sprout_skips_and_errors(outcome: &argos_core::sprout_sweep::SproutSweepOutcome) {
    for reason in &outcome.skipped {
        println!("  not swept — {reason}");
    }
    for warning in &outcome.warnings {
        eprintln!("  warning: {warning}");
    }
    if !outcome.rejected.is_empty() {
        println!();
        println!(
            "  The network refused {} note(s). Nothing moved for these, and no fee was paid:",
            outcome.rejected.len()
        );
        // One line per note, then each kind's cause and remedy once: a
        // spent note, a stale witness and an evicted transaction call for
        // different next steps, but a heavily refused run must not print a
        // paragraph per note.
        for r in &outcome.rejected {
            println!("    {}", r.summary());
        }
        let mut kinds: Vec<(
            argos_core::sprout_sweep::Refusal,
            argos_core::sprout_sweep::NoteSource,
        )> = Vec::new();
        for r in &outcome.rejected {
            if !kinds.contains(&(r.kind, r.source)) {
                kinds.push((r.kind, r.source));
            }
        }
        for (kind, source) in kinds {
            println!();
            for line in wrap_text(kind.explanation(source), 74) {
                println!("  {line}");
            }
        }
    }
    if let Some(error) = &outcome.error {
        println!();
        eprintln!("  ⚠ THE SWEEP DID NOT FINISH");
        eprintln!("    {error}");
        if !outcome.transactions.is_empty() {
            eprintln!(
                "    The {} transaction(s) listed above retain their recorded lifecycle \
                 state. Reconcile them before re-running.",
                outcome.transactions.len()
            );
        }
    }
}

fn fmt_elapsed(d: std::time::Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

fn print_sprout_nu7_warning(network: ZeckNetwork) {
    eprintln!();
    for line in wrap_text(&argos_core::sprout_sweep::nu7_recovery_warning(network), 76) {
        eprintln!("  {line}");
    }
    eprintln!();
}

/// Once a Sprout sweep has broadcast, the deadline that matters is mining:
/// "start recovery promptly" would be the wrong advice here.
fn print_sprout_nu7_broadcast_warning(
    network: ZeckNetwork,
    outcome: &argos_core::sprout_sweep::SproutSweepOutcome,
) {
    if !outcome.transactions.iter().any(|transaction| {
        matches!(
            transaction.state,
            argos_core::TxLifecycleState::Pending
                | argos_core::TxLifecycleState::SubmissionUnknown
                | argos_core::TxLifecycleState::Mined
        )
    }) {
        return;
    }
    eprintln!();
    for line in wrap_text(
        &argos_core::sprout_sweep::nu7_broadcast_warning(network),
        76,
    ) {
        eprintln!("  {line}");
    }
    eprintln!();
}

/// Tell the user what a Sprout scan actually costs, before they start one.
///
/// A Sprout scan cannot use lightwalletd — compact blocks carry no
/// JoinSplits — so it pulls full blocks from the p2p network for the whole
/// chain. Letting that begin without warning would misrepresent a multi-day,
/// hundreds-of-gigabytes job as an ordinary scan.
fn print_sprout_scan_cost_warning(network: ZeckNetwork) {
    // Follows the selected network: quoting mainnet's figures for a testnet
    // scan is simply false.
    let cost = SproutScanCost::for_network(network.into());
    eprintln!("  ⚠ RECOVERING THESE NOTES REQUIRES A FULL-BLOCK SCAN");
    eprintln!("    To start one:");
    eprintln!("      argos scan-sprout --wallet-file <this file> --destination <zs1…>");
    eprintln!();
    for line in cost.warning_lines() {
        if line.is_empty() {
            eprintln!();
            continue;
        }
        // The shared text is unwrapped so the GUI can reflow it; a terminal
        // cannot, and an unwrapped paragraph is exactly the kind of wall of
        // text people skip past.
        for wrapped in wrap_text(&line, 72) {
            eprintln!("    {wrapped}");
        }
    }
    eprintln!();
}

/// Greedy word wrap.
///
/// A line that already fits is returned verbatim rather than re-joined:
/// the warning's two-column rows align with runs of spaces, and splitting
/// on whitespace would silently collapse them.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if text.chars().count() <= width {
        return vec![text.to_owned()];
    }

    let mut out = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            out.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn print_transparent_report(report: &TransparentScanReport) {
    println!();
    println!("━━━ Transparent balances ━━━");
    println!("  Addresses checked   {}", report.addresses_checked);
    println!("  Funded addresses    {}", report.funded.len());
    println!(
        "  Total               {}",
        format_zec(report.total_zatoshis)
    );
    if report.chain_tip_height > 0 {
        println!("  Chain tip           {}", report.chain_tip_height);
    }
    println!();

    if report.funded.is_empty() {
        println!("No spendable transparent funds were found at these addresses.");
        println!();
        println!(
            "Note: this reports what is spendable now, not what the wallet ever held. \
             A wallet that was funded and later emptied reports zero here."
        );
        return;
    }

    for balance in &report.funded {
        println!(
            "  {}  {}  ({} UTXO{})",
            balance.address,
            format_zec(balance.zatoshis),
            balance.utxo_count,
            if balance.utxo_count == 1 { "" } else { "s" }
        );
    }
}

/// What to tell a user holding Sprout keys: `scan`/`sweep` are the wrong
/// tools for them, and the Sprout-specific subcommands are the right ones.
fn print_sprout_next_steps() {
    println!(
        "Sprout: `scan` and `sweep` do not move Sprout notes — those funds are not \
         yet recoverable through them. Use `argos scan-sprout` / `argos sweep-sprout`, \
         which need a full-block scan and land the value in the destination's Sapling \
         receiver."
    );
}

async fn print_sprout_inspection(
    keys: &ImportedKeys,
    network: ZeckNetwork,
    show_spent: bool,
    data_dir: &Path,
) {
    if !keys.sprout.is_empty() {
        print_sprout_nu7_warning(network);
        println!("Sprout addresses:");
        for key in &keys.sprout {
            // Encoded, not hex: a user has to be able to match this against a
            // paper backup or a block explorer, and 64 bytes of hex matches
            // nothing they have ever seen.
            let addr = argos_core::sprout_key::encode_sprout_address(
                &argos_core::sprout::SproutPaymentAddress::from_bytes(key.address),
                network,
            );
            println!("  {addr}");
        }
        println!();

        // Whether these are recoverable depends entirely on what else the
        // wallet file holds, so say which case this file is in rather than
        // making a blanket claim. Spending a Sprout note needs its value,
        // rho and r, which live only in the JoinSplit ciphertext, plus a
        // witness. A wallet with both needs no network at all; a wallet
        // with neither needs the full-block scan, which is a different
        // proposition entirely and is quoted as such.
        let recovered = recover_with_scan(keys, network, data_dir, ScanEvidence::Offline).await;
        let spending_keys = wallet_sprout_keys(keys);
        let journal = argos_core::sprout_sweep::SweepJournal::for_keys(
            data_dir,
            spending_keys.as_slice(),
            network,
        );
        let outpoints = recovered
            .notes
            .iter()
            .map(|note| note.outpoint)
            .collect::<Vec<_>>();
        let (snapshot, journal_read) = if data_dir.exists() {
            match journal.load_scoped_snapshot(&outpoints) {
                Ok(snapshot) => (snapshot, true),
                Err(err) => {
                    println!("  Sweep lifecycle journal could not be read: {err}");
                    println!("  {SPROUT_KEEP_SOURCE_WARNING}");
                    (
                        argos_core::sprout_sweep::SproutJournalSnapshot::default(),
                        false,
                    )
                }
            }
        } else {
            (
                argos_core::sprout_sweep::SproutJournalSnapshot::default(),
                true,
            )
        };
        let inventory =
            argos_core::sprout_sweep::classify_sprout_notes(&recovered.notes, &snapshot);
        let preview_plan = match sprout_preview_plan(&inventory) {
            Ok(plan) => plan,
            Err(err) => {
                println!("  Sprout sweep preview could not be computed: {err}");
                println!("  {SPROUT_KEEP_SOURCE_WARNING}");
                None
            }
        };
        print_sprout_accounting(
            keys,
            &recovered,
            show_spent,
            "argos inspect-wallet --show-spent",
        );
        print_sprout_lifecycle_entries(&snapshot);
        if sprout_nothing_left(&recovered, &inventory, &snapshot, journal_read) {
            println!("  Nothing is left to sweep: every Sprout note this file records was spent");
            println!("  by the wallet itself or is worth less than the fee to move it.");
            // Still offered: the verdict is the file's, and a spend recorded
            // against a block later reorged out would read exactly like this.
            println!(
                "  To check that against the chain: argos scan-sprout --wallet-file <this file>"
            );
            println!();
            // Quoted wherever the scan is offered: it is a multi-day,
            // hundreds-of-gigabytes run, and that must be known up front.
            print_sprout_scan_cost_warning(network);
            return;
        }
        let lifecycle_guidance =
            sprout_lifecycle_status_guidance(snapshot.entries().map(|entry| entry.state));
        if !journal_read {
            return;
        }
        if preview_plan.is_none() && lifecycle_guidance.is_some() {
            println!("  No Sprout note is ready for a new sweep.");
            for line in wrap_text(lifecycle_guidance.expect("checked above"), 74) {
                println!("  {line}");
            }
            println!();
            return;
        }
        if recovered.notes.is_empty() && snapshot.entries().next().is_none() {
            println!("  No spendable Sprout notes were recovered from this file.");
            if !recovered.issues.is_empty() {
                println!("  Why:");
                for issue in recovered.issues.iter().take(5) {
                    println!("    - {issue}");
                }
                if recovered.issues.len() > 5 {
                    println!("    ... and {} more", recovered.issues.len() - 5);
                }
            }
            println!();
            print_sprout_scan_cost_warning(network);
        } else if let Some(plan) = preview_plan {
            println!(
                "  {} spendable Sprout note(s), {} total.",
                plan.notes,
                format_zec(plan.gross_zatoshis)
            );
            println!("  These were recovered from this file alone — no scan needed.");
            println!();
            for line in wrap_text(&recovered.spent_status(), 74) {
                println!("  {line}");
            }
            println!();
            // The literal next command. A user following a guide will not
            // read --help, and a terminal state that names no next step is
            // where people give up with their funds still stranded.
            println!("  To move them:");
            println!(
                "    argos sweep-sprout --wallet-file <this file> \\\n      --destination <your zs1… or unified address> --confirm-sweep"
            );
            println!();
        } else {
            println!("  No recovered Sprout note is worth more than the fee to move it.");
        }
    }
}

/// Everything Argos recovered, printed without any network access.
///
/// This is the only useful thing it can do with a zcashd `wallet.dat`
/// today, so it must be honest about the difference between "found a
/// key" and "can move the funds".
async fn print_wallet_inspection(
    keys: &ImportedKeys,
    network: ZeckNetwork,
    show_spent: bool,
    data_dir: &Path,
) {
    println!("━━━ Recovered key material ━━━");
    println!("  Transparent keys  {}", keys.transparent.len());
    println!("  Sapling keys      {}", keys.sapling.len());
    println!("  Sprout keys       {}", keys.sprout.len());
    println!("  Sprout notes      {}", keys.sprout_notes.len());
    println!(
        "  Seed phrase       {}",
        if keys.mnemonic.is_some() {
            "recovered"
        } else {
            // Verified, not scanned from: zcashd's own keys sit under a
            // legacy account the HD scan never reaches (#229).
            keys.verified_seed_note()
                .unwrap_or("not recovered from this file")
        }
    );
    println!();

    // Printing the addresses, not just a count, is the difference between
    // a user being able to check their own balance in a block explorer and
    // being told a number they can do nothing with.
    match imported_transparent_keys(keys) {
        Ok(resolved) if !resolved.is_empty() => {
            println!("Transparent addresses:");
            for key in &resolved {
                println!("  {}", encode_transparent_address(&key.address, network));
            }
            println!();
        }
        Ok(_) => {}
        Err(err) => {
            // Never silent: a key we cannot resolve is a key the user
            // still holds and must know about.
            println!("Could not resolve some transparent keys to addresses: {err}");
            println!();
        }
    }

    if !keys.sapling.is_empty() {
        println!("Sapling addresses:");
        for key in &keys.sapling {
            // The address, never the key: an address is safe to display,
            // and the spending key must never be echoed back.
            use secrecy::ExposeSecret;
            match argos_core::imported::parse_sapling_extsk(key.extsk.expose_secret()) {
                Ok(extsk) => {
                    println!(
                        "  {}",
                        argos_core::sapling_key::default_sapling_address(&extsk, network)
                    );
                }
                Err(err) => {
                    println!("  Could not resolve a Sapling key to an address: {err}");
                }
            }
        }
        println!();
    }

    // The Sprout address list and spendability verdict live in a helper to
    // keep this function to one screen; the key/note counts above come from
    // the parser, and this adds what the recovery path can say about them.
    print_sprout_inspection(keys, network, show_spent, data_dir).await;

    // Never summarize diagnostics away: unrecovered material may still
    // exist in the original file. A locked HD key is different because
    // its recovered seed can recreate it.
    // "Every record" would be false: bookkeeping records with no key
    // material are skipped by design.
    match keys.coverage_notice() {
        None => println!("Every record that can hold a key was read."),
        Some(notice) => println!("Recovery coverage: {notice}"),
    }
    if !keys.diagnostics.is_empty() {
        println!();
        // Two different kinds of finding, printed apart. A record that
        // could not be read exists only in the file; a note about the
        // seed (an unscanned account, keys its chain derived that the
        // file lacks) is not a record that failed to read, and calling
        // it one told the user something false about both.
        let (unread, seed): (Vec<_>, Vec<_>) =
            keys.diagnostics.iter().partition(|d| !d.is_about_seed());
        if !unread.is_empty() {
            println!("{} import diagnostic(s):", unread.len());
            for diagnostic in &unread {
                println!("  {diagnostic}");
            }
        }
        if !seed.is_empty() {
            if !unread.is_empty() {
                println!();
            }
            println!("About this wallet's seed:");
            for diagnostic in &seed {
                println!("  {diagnostic}");
            }
        }
        if keys.coverage().may_hide_funds() {
            println!();
            println!(
                "Keep the original wallet file. It may contain keys or records Argos has not recovered."
            );
        }
    }
    println!();

    // Sprout is its own path and its own caveat, stated before the route
    // advice so it cannot be lost in it. This used to ride on the blanket
    // "seedless wallets cannot move funds" message, which meant the warning
    // was only correct by accident — and disappeared the moment that message
    // became accurate about Sapling and transparent funds.
    //
    // Always says something, because a Sprout key count has already been
    // printed above: the parser is unconditional. Silence would leave keys on
    // screen with no account of them.
    if !keys.sprout.is_empty() {
        print_sprout_next_steps();
        println!();
    }

    // Driven by the classifier rather than by `mnemonic.is_some()`, which was
    // telling every seedless wallet that Argos "cannot yet move funds held by
    // them" — untrue for both remaining routes, and the same false
    // unrecoverable claim that dead-ended the GUI. A `match` also means a new
    // route forces this copy to be updated instead of silently falling into
    // the wrong arm.
    match argos_core::key_source::classify_recovery_route(keys) {
        argos_core::key_source::RecoveryRoute::Hd => {
            println!("Next: run `argos scan --wallet-file <path>` to check these keys for funds.");
        }
        argos_core::key_source::RecoveryRoute::Combined => {
            println!("Next: run `argos scan --wallet-file <path>` for one combined scan of the recovered seed and standalone keys. Keep the original wallet file until every recovered balance has been moved and confirmed.");
        }
        argos_core::key_source::RecoveryRoute::ImportedAccounts => {
            println!(
                "Next: run `argos scan --wallet-file <path>` to check these keys for funds. \
                 Its stored Sapling keys are scanned as imported accounts, one per key; \
                 balances are visible and transparent funds can be swept."
            );
        }
        argos_core::key_source::RecoveryRoute::TransparentOnly => {
            println!(
                "Next: run `argos scan --wallet-file <path>` to check these keys for funds. \
                 This wallet holds only transparent keys, which are scanned and swept \
                 directly — no HD seed is needed."
            );
        }
        argos_core::key_source::RecoveryRoute::Nothing => {
            println!(
                "This wallet file contains no transparent or Sapling keys, so there is \
                 nothing to scan."
            );
        }
    }
}

/// Resolve the birthday height for a scan.
///
/// `seed_phrase` is `None` for a wallet file with no recoverable mnemonic.
/// Auto-detection then has two routes: a seed phrase is probed on chain as
/// HD-derived addresses, and a zcashd wallet.dat is dated from its own key
/// creation times. Anything else — a ZecWallet Lite file whose seed was not
/// recovered, or keys from --sapling-key-file alone — has neither, and the
/// other two routes stay available to it.
async fn resolve_birthday(
    cli: &Cli,
    seed_phrase: Option<&SecretString>,
    imported: Option<&ImportedKeys>,
    keys_added_from_key_file: usize,
    network: ZeckNetwork,
) -> Result<u32> {
    if cli.birthday_auto_detect {
        let Some(seed_phrase) = seed_phrase else {
            let zcashd_keys = match (imported, cli.wallet_file.as_deref()) {
                (Some(keys), Some(path)) if wallet_file_is_zcashd(path)? => Some(keys),
                _ => None,
            };
            let keys = zcashd_keys.ok_or_else(|| {
                anyhow::anyhow!(
                    "--birthday-auto-detect needs a seed phrase to probe on chain, or a zcashd \
                     wallet.dat whose key creation times date it, and these keys come with \
                     neither. Pass --birthday <height> or --birthday-date <YYYY-MM-DD> instead."
                )
            })?;
            return Ok(
                detect_wallet_dat_birthday(cli, keys, keys_added_from_key_file, network).await,
            );
        };
        eprintln!("Auto-detecting wallet birthday from on-chain history…");
        let result = detect_birthday(seed_phrase, network, &cli.lightwalletd_url, |msg| {
            eprintln!("  {msg}")
        })
        .await
        .context("birthday auto-detection failed")?;
        eprintln!("✓ {}", result.message);
        Ok(result.birthday)
    } else if let Some(date) = &cli.birthday_date {
        Ok(estimate_birthday_from_date(date, &cli.lightwalletd_url).await?)
    } else {
        Ok(cli.birthday_or_default())
    }
}

/// Whether a wallet file is zcashd's, the only format whose keys carry
/// creation times. A ZecWallet Lite file without its seed would otherwise
/// be reported as a wallet.dat whose keys zcashd left undated.
fn wallet_file_is_zcashd(path: &Path) -> Result<bool> {
    let bytes = argos_core::wallet_file::read_wallet_file(path)
        .with_context(|| format!("failed to read wallet file {}", path.display()))?;
    Ok(matches!(
        argos_wallet_import::sniff(&bytes)?,
        argos_wallet_import::WalletFormat::Zcashd
    ))
}

/// `--birthday-auto-detect` for a seedless zcashd wallet.dat.
///
/// Never fails: when nothing can be dated, the scan starts from the
/// beginning of the Sapling pool, which is slow but cannot miss a note.
///
/// `keys_added_from_key_file` is how many of `keys`' Sapling keys came from
/// --sapling-key-file rather than the wallet file, so the message can say
/// where the undated keys came from.
async fn detect_wallet_dat_birthday(
    cli: &Cli,
    keys: &ImportedKeys,
    keys_added_from_key_file: usize,
    network: ZeckNetwork,
) -> u32 {
    use argos_core::WalletBirthdaySource;

    eprintln!("Dating the wallet file from its key creation times…");
    // Only scan and sweep get here, and neither reads Sprout keys from
    // --sprout-key-file, so there are no extra Sprout keys to declare.
    let found = argos_core::detect_wallet_file_birthday(
        keys,
        &[],
        network,
        keys_added_from_key_file,
        argos_core::unix_time_now(),
        Some(&cli.lightwalletd_url),
        |msg| eprintln!("  {msg}"),
    )
    .await;
    let Some(height) = found.height else {
        for line in wrap_text(&found.message, 76) {
            eprintln!("  {line}");
        }
        let start = sapling_activation_height(network);
        eprintln!(
            "No birthday could be detected; scanning from the start of the Sapling pool \
             (block {start})."
        );
        // On mainnet this equals `birthday_or_default()`, so an auto-detect
        // that finds nothing keys the same workspace as a plain `scan` and a
        // resume across the two is not lost. Block 1 would clamp to the same
        // start but key a different workspace.
        return start;
    };
    let source = match found.source {
        WalletBirthdaySource::TransparentUtxos => {
            "on-chain unspent transparent outputs. That is an upper bound: the wallet may be \
             older"
        }
        WalletBirthdaySource::WalletMetadata | WalletBirthdaySource::None => {
            "the wallet file's key creation times"
        }
    };
    let date = match network {
        ZeckNetwork::Mainnet => format!(
            " (about {})",
            argos_core::estimate_date_from_height_offline(height)
        ),
        ZeckNetwork::Testnet => String::new(),
    };
    eprintln!("✓ Birthday: block {height}{date}, from {source}.");
    for line in wrap_text(&found.message, 76) {
        eprintln!("  {line}");
    }
    if network == ZeckNetwork::Mainnet && height <= 419_200 {
        eprintln!(
            "  That is before Sapling activation. This scan still starts just past it, where \
             Sapling and transparent history begin; only `argos scan-sprout` reads earlier \
             blocks."
        );
    }
    height
}

/// Point this process at the harness's private regtest chain.
///
/// Compiled out unless the crate is built with `argos-network`, which a
/// released build never is. That gate — not this env var — is what stops a
/// shipped `argos` from being talked onto foreign consensus parameters: with
/// the feature off, `set_regtest_consensus_params` does not exist to call.
///
/// The env var exists so that even a feature-enabled test binary only
/// retargets when the harness explicitly asks it to.
#[cfg(feature = "argos-network")]
fn install_regtest_params_if_requested() -> Result<()> {
    if std::env::var_os("ARGOS_REGTEST_CONSENSUS").is_none() {
        return Ok(());
    }
    argos_core::workspace::set_regtest_consensus_params(
        argos_core::workspace::regtest_local_network(),
    )?;
    tracing::warn!(
        "regtest consensus parameters installed via ARGOS_REGTEST_CONSENSUS; \
         this build is not a release build"
    );
    Ok(())
}

#[cfg(not(feature = "argos-network"))]
fn install_regtest_params_if_requested() -> Result<()> {
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_cli_from(std::env::args_os()).unwrap_or_else(|err| err.exit());
    if let Some(requested) = cli.scan_batch_size {
        let used = argos_core::scan::set_sync_batch_size(requested);
        if used != requested {
            eprintln!("--scan-batch-size {requested} is out of range; using {used}.");
        }
    }
    init_tracing(cli.verbose)?;
    refuse_unconsumed_key_sources(&cli)?;
    refuse_unconsumed_birthday_skip(&cli)?;

    install_regtest_params_if_requested()?;

    // Gate the network/funds-moving commands on Terms of Service acceptance.
    // `show-keys` is purely local key derivation and is intentionally ungated.
    if command_requires_tos(&cli.command) {
        ensure_tos_accepted(&cli.data_dir, cli.accept_tos)?;
    }

    let network: ZeckNetwork = cli.network.into();

    // Reconciliation uses the durable network registry, not a key source or
    // one-shot scan handle. Dispatch before any wallet import or seed prompt.
    if let Commands::Reconcile { txid, resubmit } = &cli.command {
        return run_reconcile(
            &cli.data_dir,
            network,
            &cli.lightwalletd_url,
            &cli.confirmation_source,
            txid.as_deref(),
            *resubmit,
        )
        .await;
    }

    // `scan-sprout` is dispatched here, before key-source resolution, because
    // it needs no HD seed: its keys come from a key file or from a wallet
    // file's Sprout records. Falling through would prompt for a seed phrase
    // the user does not have and cannot supply.
    if let Commands::ScanSprout {
        destination,
        peer,
        sprout_params,
        confirm_sweep,
    } = &cli.command
    {
        ensure_tos_accepted(&cli.data_dir, cli.accept_tos)?;
        let wallet_keys = match &cli.wallet_file {
            Some(path) => Some(load_wallet_file(path, network)?),
            None => None,
        };
        let SproutScanKeys {
            all: keys,
            from_key_file,
        } = collect_sprout_scan_keys(
            cli.sprout_key_file.as_deref(),
            wallet_keys.as_ref(),
            network,
        )?;
        let plan = sprout_scan_plan(
            wallet_keys.as_ref(),
            from_key_file.as_slice(),
            network,
            cli.birthday,
            cli.no_birthday_skip,
            argos_core::unix_time_now(),
        );
        // Before anything touches the network, so the user sees what will
        // be left undecrypted even when the run stops early.
        eprintln!("{}", plan.line);
        if plan.decrypt_from.is_some() {
            eprintln!(
                "To decrypt every block instead, re-run with --no-birthday-skip or an \
                 earlier --birthday."
            );
        }
        return scan_sprout(
            keys.as_slice(),
            network,
            &cli.lightwalletd_url,
            &cli.confirmation_source,
            &cli.data_dir,
            peer,
            destination.as_deref(),
            sprout_params.clone(),
            *confirm_sweep,
            plan.decrypt_from,
        )
        .await;
    }

    // `key_source` is what the scanner and sweeper use. `seed_phrase` is
    // the same key material in the one form two local-only paths still
    // need it in — birthday auto-detection and `show-keys` — and is
    // absent for a wallet file with no recoverable mnemonic.
    // Sapling keys merged in from --sapling-key-file. They carry no creation
    // time, and the birthday message has to say they came from outside the
    // wallet file rather than blame the file.
    let mut keys_added_from_key_file = 0;
    let (key_source, seed_phrase, imported): (
        Arc<dyn KeySource>,
        Option<SecretString>,
        Option<Arc<ImportedKeySource>>,
    ) = match (&cli.wallet_file, &cli.sapling_key_file) {
        (Some(path), key_file) => {
            let mut keys = load_wallet_file(path, network)?;
            if let Some(key_path) = key_file {
                // A wallet with a mnemonic takes the Combined route, which
                // registers these keys beside the seed's accounts; a
                // seedless one scans them as imported accounts.
                keys_added_from_key_file = argos_core::sapling_key::merge_standalone_sapling_keys(
                    &mut keys,
                    load_sapling_key_file(key_path, network)?,
                )?;
            }
            let phrase = keys.mnemonic.clone();
            // `inspect-wallet` prints a fuller version of this below, so
            // don't say it twice.
            if !matches!(cli.command, Commands::InspectWallet { .. }) {
                eprintln!(
                    "Imported {} key(s) from {}.",
                    keys.total_keys(),
                    path.display()
                );
                if !keys.diagnostics.is_empty() {
                    eprintln!(
                        "{} record(s) could not be read — run `argos inspect-wallet \
                         --wallet-file {}` to see them.",
                        keys.diagnostics.len(),
                        path.display()
                    );
                }
            }
            let source = Arc::new(ImportedKeySource::new(keys));
            (source.clone(), phrase, Some(source))
        }
        (None, Some(key_path)) => {
            // A key file is its own key source. There is no seed behind it,
            // so `seed_phrase` stays `None` — birthday auto-detection and
            // `show-keys` are unavailable, exactly as for a wallet file with
            // no recoverable mnemonic.
            let keys = load_sapling_key_file(key_path, network)?;
            if !matches!(cli.command, Commands::InspectWallet { .. }) {
                eprintln!(
                    "Loaded {} Sapling key(s) from {}.",
                    keys.sapling.len(),
                    key_path.display()
                );
            }
            let source = Arc::new(ImportedKeySource::new(keys));
            (source.clone(), None, Some(source))
        }
        (None, None) => {
            // Bail before prompting: an interactive seed prompt for a
            // command that only reads a wallet file is pure confusion.
            if matches!(cli.command, Commands::InspectWallet { .. }) {
                bail!("inspect-wallet needs --wallet-file or --sapling-key-file");
            }
            let phrase = load_seed_phrase(cli.seed_file.clone())?;
            (
                Arc::new(SeedKeySource::new(phrase.clone())),
                Some(phrase),
                None,
            )
        }
    };

    // Even an ordinary HD or imported-key recovery can leave Sprout behind.
    // Warn as soon as those keys are known, before either scan route starts.
    if matches!(cli.command, Commands::Scan | Commands::Sweep { .. })
        && imported
            .as_ref()
            .is_some_and(|source| !source.keys().sprout.is_empty())
    {
        print_sprout_nu7_warning(network);
    }

    // Only the seed-phrase sweep attaches a memo or a donation; the
    // imported-key and transparent-only sweeps send neither. Say so before
    // the scan, not after it. A memo is refused outright, because a dropped
    // exchange-deposit memo can lose the deposit. A donation is only reported.
    if let Commands::Sweep {
        destination,
        memo,
        donation_rate,
        donor_email,
        ..
    } = &cli.command
    {
        if seed_phrase.is_none() {
            argos_core::refuse_memo_without_seed(memo.as_deref())?;
            // With a mnemonic, transparent keys may overlap discovered HD
            // receivers. The core sweep checks any remaining direct leg
            // after scanning; only a seedless source is certain here.
            if let Some(source) = imported.as_ref() {
                argos_core::transparent_recovery::refuse_destination_the_transparent_leg_cannot_reach(
                    source.keys(),
                    destination,
                    network,
                )?;
            }
            // --donor-email only ever labels a donation, so it gets the same
            // note: nothing it names will be sent.
            if donation_rate.is_some() || donor_email.is_some() {
                eprintln!(
                    "Note: a donation (--donation-rate, --donor-email) applies only when \
                     sweeping from a seed phrase. This wallet has none, so this sweep sends \
                     no donation."
                );
            }
        }
    }

    // A wallet with no HD seed cannot be scanned as accounts, but its
    // transparent keys can still be recovered directly — no account model
    // is involved. Dispatch before the birthday gate, which only makes
    // sense for an HD scan.
    if let Some(source) = imported.as_ref() {
        let keys = source.keys();
        if is_transparent_only(keys) {
            match &cli.command {
                Commands::Scan => {
                    warn_about_uncovered_pools(keys, false);
                    let resolved = imported_transparent_keys(keys)?;
                    let report =
                        scan_transparent_only(&resolved, network, &cli.lightwalletd_url).await?;
                    print_transparent_report(&report);
                    if echo_scan_summary(std::io::stdout().is_terminal()) {
                        eprintln!();
                        eprintln!(
                            "Scan finished: {} funded of {} transparent address(es) checked, {} \
                             in total. Full results were written to stdout.",
                            report.funded.len(),
                            report.addresses_checked,
                            format_zec(report.total_zatoshis)
                        );
                    }
                    return Ok(());
                }
                Commands::Sweep {
                    destination,
                    max_fee,
                    dry_run,
                    confirm_sweep,
                    ..
                } => {
                    warn_about_uncovered_pools(keys, false);
                    let resolved = imported_transparent_keys(keys)?;
                    return run_transparent_sweep(
                        &resolved,
                        &cli.data_dir,
                        network,
                        &cli.lightwalletd_url,
                        destination,
                        *max_fee,
                        *dry_run,
                        *confirm_sweep,
                    )
                    .await;
                }
                _ => {}
            }
        } else if keys.mnemonic.is_none()
            && matches!(cli.command, Commands::Scan | Commands::Sweep { .. })
        {
            // Imported-account path: Sapling and transparent are scanned
            // together, so only Sprout is left uncovered — but it still
            // must be said before any balance appears.
            warn_about_uncovered_pools(keys, true);
        } else if matches!(cli.command, Commands::Scan | Commands::Sweep { .. }) {
            // A seed-bearing wallet (ZWL) covers every pool, but records it
            // could not decrypt can still hide funds.
            warn_about_partial_import(keys);
        }
    }

    let birthday = if command_uses_birthday_inputs(&cli.command) {
        Some(
            resolve_birthday(
                &cli,
                seed_phrase.as_ref(),
                imported.as_ref().map(|source| source.keys()),
                keys_added_from_key_file,
                network,
            )
            .await?,
        )
    } else {
        None
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
        Commands::InspectWallet { show_spent } => {
            let source = imported.expect("--wallet-file is required and was checked above");
            print_wallet_inspection(source.keys(), network, show_spent, &cli.data_dir).await;
        }

        // Dispatched above, before key-source resolution, so that it never
        // prompts for a seed phrase it does not need.
        Commands::ScanSprout { .. } => unreachable!("scan-sprout returns earlier"),
        Commands::Reconcile { .. } => {
            unreachable!("reconcile returns before key-source resolution")
        }

        Commands::SweepSprout {
            destination,
            sprout_params,
            dry_run,
            confirm_sweep,
            peer,
        } => {
            let source = imported.ok_or_else(|| {
                anyhow::anyhow!(
                    "sweep-sprout recovers notes from a legacy wallet file; pass \
                     --wallet-file <path>"
                )
            })?;
            sweep_sprout(
                source.keys(),
                network,
                &cli.data_dir,
                &peer,
                &cli.lightwalletd_url,
                &cli.confirmation_source,
                &destination,
                sprout_params,
                SweepGate {
                    dry_run,
                    confirm_sweep,
                },
            )
            .await?;
        }

        Commands::ShowKeys => {
            let phrase = seed_phrase.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "{} has no recoverable seed phrase, so there are no HD accounts to \
                     show. Use `argos inspect-wallet --wallet-file <path>` instead.",
                    key_source.describe()
                )
            })?;
            let accounts = derive_accounts(phrase, network, account_count)?;
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
            let birthday = birthday.expect("scan command requires birthday");
            let service = RecoveryService::new();
            let handle = service
                .start_scan_from_key_source(
                    ScanConfig {
                        birthday,
                        num_accounts: cli.num_accounts,
                        gap_limit: cli.gap_limit,
                        lightwalletd_url: cli.lightwalletd_url.clone(),
                        confirmation_sources: argos_core::lightwalletd::parse_confirmation_sources(
                            &cli.confirmation_source
                                .iter()
                                .map(String::as_str)
                                .collect::<Vec<_>>(),
                        )?,
                        data_dir: cli.data_dir.clone(),
                        network,
                        label: String::new(),
                        transparent_scan: Some(transparent_scan_config(
                            cli.transparent_index_start,
                            cli.transparent_index_count,
                            cli.transparent_change,
                        )?),
                    },
                    key_source.clone(),
                )
                .await?;

            let progress = wait_for_scan(&service, &handle).await?;
            print_scan_result(&progress);
            if echo_scan_summary(std::io::stdout().is_terminal()) {
                let totals: Vec<u64> = progress.accounts.iter().map(|a| a.total_zatoshis).collect();
                eprintln!();
                eprintln!(
                    "{}",
                    scan_summary_line(progress.phase, &totals, progress.error.as_deref())
                );
            }
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
            let birthday = birthday.expect("sweep command requires birthday");
            let address = validate_destination_address(&destination, network)?;
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
                .start_scan_from_key_source(
                    ScanConfig {
                        birthday,
                        num_accounts: cli.num_accounts,
                        gap_limit: cli.gap_limit,
                        lightwalletd_url: cli.lightwalletd_url.clone(),
                        confirmation_sources: argos_core::lightwalletd::parse_confirmation_sources(
                            &cli.confirmation_source
                                .iter()
                                .map(String::as_str)
                                .collect::<Vec<_>>(),
                        )?,
                        data_dir: cli.data_dir.clone(),
                        network,
                        label: String::new(),
                        transparent_scan: Some(transparent_scan_config(
                            cli.transparent_index_start,
                            cli.transparent_index_count,
                            cli.transparent_change,
                        )?),
                    },
                    key_source.clone(),
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
                reviewed_fee_zatoshis: None,
                donation_rate,
                donor_email,
            };
            let reviewed = service.propose_sweep(&handle, request).await?;
            print_sweep_preview(&reviewed.proposal);

            if dry_run {
                println!();
                println!("Dry run complete. Re-run with --confirm-sweep to broadcast.");
                return Ok(());
            }

            if confirm_sweep {
                println!();
                println!("Broadcasting sweep transactions…");
                let execution = service.execute_sweep(&handle, &reviewed.proposal_id).await;
                match execution {
                    Ok(outcome) => {
                        println!();
                        for result in &outcome.transactions {
                            println!(
                                "  account {}  {} ({})  txid {}  fee {}",
                                result.source_account,
                                result.status,
                                sweep_status_label(result.status),
                                result.txid.as_deref().unwrap_or("unknown"),
                                format_zec(result.fee_zatoshis),
                            );
                            if result.status == argos_core::TxLifecycleState::Mined {
                                if let Some(height) = result.confirmed_height {
                                    println!("    mined at block {height}");
                                }
                            }
                            println!("    evidence: {}", result.detail);
                        }
                        println!();
                        // Accounts that held a balance but moved nothing (all
                        // spendable value below the ZIP-317 fee floor): surface
                        // the skip rather than leaving it silent.
                        if !outcome.skipped_accounts.is_empty() {
                            println!(
                                "Skipped {} account(s) with balances below the ZIP-317 fee floor:",
                                outcome.skipped_accounts.len()
                            );
                            for skipped in &outcome.skipped_accounts {
                                println!(
                                    "  account {}  {}  {}",
                                    skipped.account_index,
                                    format_zec(skipped.gross_zatoshis),
                                    skipped.reason
                                );
                            }
                            println!();
                        }
                        let statuses: Vec<_> =
                            outcome.transactions.iter().map(|tx| tx.status).collect();
                        if let Some(donation_line) = sweep_donation_line(
                            donation_rate,
                            outcome.total_donation_zatoshis,
                            &statuses,
                            outcome.donation_note.as_deref(),
                        ) {
                            println!("{donation_line}");
                            println!();
                        }
                        match outcome.error {
                            None => println!(
                                "{}",
                                sweep_completion_guidance_with_skips(
                                    &statuses,
                                    !outcome.skipped_accounts.is_empty(),
                                    outcome.follow_up_review_required
                                )
                            ),
                            // A mid-sequence abort: the transactions above were
                            // already broadcast and are irreversible, but the
                            // remaining accounts were not swept (audit Issue E).
                            // Make this loud so the operator does not assume
                            // nothing was sent and retry into a double-broadcast.
                            Some(message) => {
                                if outcome.transactions.iter().any(|tx| {
                                    tx.status == argos_core::TxLifecycleState::SubmissionUnknown
                                }) {
                                    eprintln!("A listed transaction may already have reached the network; do not retry or discard the source wallet. Reconcile its txid before any further sweep.");
                                } else {
                                    eprintln!("Sweep aborted with the transaction results listed above. Keep the source wallet and recovery workspace; verify each txid before a new proposal. Remaining accounts were not swept.");
                                }
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

/// Require Terms of Service acceptance before a network/funds-moving command.
///
/// Skips silently if the current TOS version was already accepted under
/// `data_dir`. Otherwise: `--accept-tos` records acceptance non-interactively;
/// an interactive TTY gets a short notice and a `y/N` prompt; a non-interactive
/// run without the flag errors with guidance (so it fails closed).
fn ensure_tos_accepted(data_dir: &Path, accept_flag: bool) -> Result<()> {
    if argos_core::is_tos_accepted(data_dir) {
        return Ok(());
    }

    if accept_flag {
        record_tos(data_dir)?;
        eprintln!(
            "Argos Terms of Service ({}) accepted via --accept-tos.",
            argos_core::TOS_VERSION
        );
        return Ok(());
    }

    let notice = format!(
        "\n\
         ──────────────────────────────────────────────────────────────\n\
         Argos Terms of Service ({version})\n\n\
         By accepting, you agree to the Argos Terms of Service, which include a\n\
         MANDATORY BINDING ARBITRATION clause and a WAIVER OF JURY TRIAL and\n\
         CLASS ACTIONS, and limits on Sovright's liability.\n\n\
         Read the full Terms in the Argos desktop app, or at:\n  \
         https://github.com/sovright/argos/blob/main/crates/zeck-core/assets/terms-of-service.md\n\
         ──────────────────────────────────────────────────────────────",
        version = argos_core::TOS_VERSION
    );

    if !std::io::stdin().is_terminal() {
        bail!(
            "{notice}\n\nThe Terms of Service must be accepted before scanning or sweeping. \
             Re-run with --accept-tos to accept them non-interactively."
        );
    }

    eprintln!("{notice}");
    eprint!("Accept these Terms? [y/N]: ");
    std::io::stderr().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .context("reading Terms of Service response")?;
    let answer = answer.trim().to_ascii_lowercase();
    if answer == "y" || answer == "yes" {
        record_tos(data_dir)?;
        eprintln!("Terms of Service accepted.");
        Ok(())
    } else {
        bail!("Terms of Service not accepted; aborting.");
    }
}

/// Record TOS acceptance under `data_dir` stamped with the current Unix time.
fn record_tos(data_dir: &Path) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    argos_core::record_tos_acceptance(data_dir, now)
        .context("recording Terms of Service acceptance")
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
        let contents = read_secret_text_file(&path)
            .with_context(|| format!("failed to read seed file {}", path.display()))?;
        return Ok(SecretString::new(contents.as_str()?.trim().to_owned()));
    }

    let phrase = SecretString::new(
        Password::new()
            .with_prompt("Enter your seed phrase (12, 15, 18, 21 or 24 words)")
            .allow_empty_password(false)
            .interact()
            .context("failed to read seed phrase from terminal")?,
    );

    Ok(SecretString::new(phrase.expose_secret().trim().to_owned()))
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
    bar.set_style(ProgressStyle::with_template("{spinner:.green} {msg}")?.tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "));
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
        Self {
            samples: VecDeque::new(),
            last_total: 0,
        }
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

/// One line for stderr when a scan ends: whether it finished, what it
/// found, and that the full result is on stdout. Needed because the result
/// goes to stdout alone — redirect that, and a finished scan looks, on the
/// terminal, exactly like one that found nothing.
fn scan_summary_line(phase: ScanPhase, account_totals: &[u64], error: Option<&str>) -> String {
    match phase {
        ScanPhase::Complete => {
            let total = account_totals
                .iter()
                .fold(0u64, |sum, v| sum.saturating_add(*v));
            format!(
                "Scan finished: {} account(s), {} in total (Sapling, Orchard and transparent; \
                 Sprout is not scanned here). Full results were written to stdout.",
                account_totals.len(),
                format_zec(total)
            )
        }
        ScanPhase::Cancelled => {
            "Scan cancelled. Progress is saved; re-run the same command to resume. Partial \
             results were written to stdout."
                .to_owned()
        }
        _ => format!(
            "Scan did not finish: {}. Details were written to stdout.",
            error.unwrap_or("no reason was given")
        ),
    }
}

/// Only when stdout is not a terminal: on one, the result is already on
/// screen and the line would repeat it.
fn echo_scan_summary(stdout_is_terminal: bool) -> bool {
    !stdout_is_terminal
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
    println!(
        "{:<8}  {:>16}  {:>16}  {:>16}  Status",
        "Account", "Sapling", "Orchard", "Transparent"
    );
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
            println!(
                "  Transparent receive:  {}",
                account.transparent_receive_address
            );
            println!(
                "  Transparent change:   {}",
                account.transparent_change_address
            );
            println!();
        }
    }
}

fn sweep_status_label(status: argos_core::TxLifecycleState) -> &'static str {
    use argos_core::TxLifecycleState as State;
    match status {
        State::NotSubmitted => "Not submitted.",
        State::SubmissionUnknown => {
            "Submission uncertain — may already be on the network. Do not retry."
        }
        State::Pending => "Broadcast — awaiting independent confirmation.",
        State::Mined => "Mined — independently confirmed.",
        State::Expired => "Expired — rescan before rebuilding.",
        State::Rejected => "Rejected by the node.",
    }
}

fn sweep_donation_line(
    donation_rate: Option<f64>,
    total_zatoshis: u64,
    states: &[argos_core::TxLifecycleState],
    donation_note: Option<&str>,
) -> Option<String> {
    use argos_core::TxLifecycleState as State;
    if donation_rate.is_none() && total_zatoshis == 0 {
        return None;
    }
    if states.contains(&State::SubmissionUnknown) {
        return Some("Donation status and amount are uncertain. Reconcile the transaction txid before reporting a donation total.".to_owned());
    }
    if states.contains(&State::Pending) {
        return Some(format!("Proposed donation: {}. Awaiting independent confirmation; reconcile pending txids before reporting a donated amount.{}", format_zec(total_zatoshis), if states.contains(&State::Expired) { " An expired transaction also requires a rescan." } else { "" }));
    }
    if states.contains(&State::Expired) {
        return Some(format!("Planned donation of {} is not confirmed. The transaction expired; rescan before rebuilding.", format_zec(total_zatoshis)));
    }
    if states.contains(&State::Rejected) || states.contains(&State::NotSubmitted) {
        return Some(
            if states
                .iter()
                .all(|state| matches!(state, State::Rejected | State::NotSubmitted))
            {
                "No donation was sent or confirmed; the transaction was rejected or not submitted."
                    .to_owned()
            } else {
                "A donation total is not confirmed for this sweep. Review the rejected or unsubmitted transaction before reporting a donated amount.".to_owned()
            },
        );
    }
    if total_zatoshis == 0 {
        if let Some(note) = donation_note {
            return Some(note.to_owned());
        }
        if states.is_empty() {
            return Some("No donation was sent; no transaction was submitted.".to_owned());
        }
        return Some(
            "No donation was sent; all listed transactions mined without a donation.".to_owned(),
        );
    }
    if !states.is_empty() && states.iter().all(|state| *state == State::Mined) {
        Some(format!(
            "Donated to the Argos project: {}",
            format_zec(total_zatoshis)
        ))
    } else {
        Some("Donation total is not confirmed. Review the transaction results before reporting a donated amount.".to_owned())
    }
}

fn sweep_completion_guidance_with_skips(
    states: &[argos_core::TxLifecycleState],
    has_skipped_accounts: bool,
    follow_up_review_required: bool,
) -> &'static str {
    if has_skipped_accounts
        && !follow_up_review_required
        && !states.is_empty()
        && states
            .iter()
            .all(|state| *state == argos_core::TxLifecycleState::Mined)
    {
        return "Every listed transaction mined, but at least one account was not swept. Keep the source wallet and recovery workspace; review the skipped balance before a new proposal.";
    }
    sweep_completion_guidance(states, follow_up_review_required)
}

fn sweep_completion_guidance(
    states: &[argos_core::TxLifecycleState],
    follow_up_review_required: bool,
) -> &'static str {
    use argos_core::TxLifecycleState as State;
    if follow_up_review_required {
        if states.contains(&State::Expired) && states.contains(&State::SubmissionUnknown) {
            return "A shielding submission may already have moved; do not retry. Reconcile its txid. Another shielding transaction expired; rescan before rebuilding and review a new proposal before sending shielded funds. Keep the source wallet and recovery workspace.";
        }
        if states.contains(&State::Expired) && states.contains(&State::Pending) {
            return "A shielding transaction is awaiting independent confirmation; reconcile its txid. Another shielding transaction expired; rescan before rebuilding and review a new proposal before sending shielded funds. Keep the source wallet and recovery workspace.";
        }
        if states.contains(&State::Expired) {
            return "A shielding transaction expired. Keep the source wallet and recovery workspace; rescan before rebuilding and review a new proposal before sending shielded funds.";
        }
        if states.contains(&State::SubmissionUnknown) {
            return "Shielding submission may already have moved. Do not retry. Keep the source wallet and recovery workspace; reconcile the txid, then rescan and review a new proposal after mining.";
        }
        if states.contains(&State::Pending) {
            return "Shielding transaction awaits independent confirmation. Keep the source wallet and recovery workspace; reconcile its txid, then rescan and review a new proposal after mining.";
        }
        return "Shielding stage submitted. Keep the source wallet and recovery workspace. After every shielding transaction mines, rescan and review a new proposal before sending shielded funds.";
    }
    if states.contains(&State::Expired) && states.contains(&State::SubmissionUnknown) {
        return "A submission may already have moved; do not retry. Reconcile its txid. Another transaction expired; rescan before rebuilding. Keep the source wallet and recovery workspace.";
    }
    if states.contains(&State::Expired) && states.contains(&State::Pending) {
        return "A transaction is awaiting independent confirmation; reconcile its txid. Another transaction expired; rescan before rebuilding. Keep the source wallet and recovery workspace.";
    }
    if states.contains(&State::SubmissionUnknown) {
        return "A transaction may already have moved. Do not retry. Keep the source wallet and recovery workspace; reconcile its txid before a new proposal.";
    }
    if states.contains(&State::Pending) {
        return "A transaction is awaiting independent confirmation. Keep the source wallet and recovery workspace until every submitted transaction mines.";
    }
    if states.contains(&State::Expired) {
        return "A transaction expired. Keep the source wallet and recovery workspace; rescan before rebuilding.";
    }
    if states.contains(&State::Rejected) {
        return "A transaction was rejected by the node. Review the evidence before a new proposal.";
    }
    if !states.is_empty() && states.iter().all(|state| *state == State::Mined) {
        return "Sweep complete. Every submitted transaction was independently confirmed as mined.";
    }
    if states.contains(&State::Mined) {
        return "A transaction mined, but this sweep did not finish. Keep the source wallet and recovery workspace; review the remaining results before a new proposal.";
    }
    "No transaction was submitted. Review the details before trying again."
}

fn print_sweep_preview(proposal: &SweepProposal) {
    println!();
    println!("Sweep preview:");
    println!(
        "  Send:        {}",
        format_zec(proposal.total_send_zatoshis)
    );
    println!("  Fee:         {}", format_zec(proposal.total_fee_zatoshis));
    println!(
        "  Net receive: {}",
        format_zec(proposal.net_received_zatoshis)
    );

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
        return "Scan stopped before completion. Re-run with the same flags to resume.".to_string();
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
        .map(|c| {
            if c == '\'' {
                "''".to_string()
            } else {
                c.to_string()
            }
        })
        .collect();
    format!("'{escaped}'")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preview_note(value: u64, id: u8) -> argos_core::sprout_recovery::SpendableSproutNote {
        let a_sk = [0x42; 32];
        let address = argos_core::sprout::SproutPaymentAddress::from_spending_key(&a_sk);
        let rho = [0x11; 32];
        let r = [0x22; 32];
        argos_core::sprout_recovery::SpendableSproutNote {
            note: argos_core::sprout::SproutNotePlaintext {
                value,
                rho,
                r,
                memo: [0; 512],
            },
            a_sk,
            address,
            commitment: argos_core::sprout::note_commitment(address.a_pk(), value, &rho, &r),
            anchor: [0; 32],
            witness_path: vec![0; argos_core::sprout_witness::WITNESS_PATH_SIZE],
            outpoint: argos_core::argos_wallet_import::keys::JsOutPoint {
                txid: [id; 32],
                js_index: 0,
                output_index: 0,
            },
        }
    }

    #[test]
    fn cli_preview_counts_only_executable_ready_notes_and_cannot_wrap() {
        let empty = argos_core::sprout_sweep::SproutJournalSnapshot::default();
        let dust = preview_note(argos_core::sprout_sweep::SPROUT_SWEEP_FEE, 0x10);
        let dust = [dust];
        let dust_inventory = argos_core::sprout_sweep::classify_sprout_notes(&dust, &empty);
        assert_eq!(sprout_preview_plan(&dust_inventory).unwrap(), None);

        let dir = tempfile::tempdir().unwrap();
        let journal = argos_core::sprout_sweep::SweepJournal::for_keys(
            dir.path(),
            &[[0x42; 32]],
            argos_core::ZeckNetwork::Mainnet,
        );
        std::fs::write(
            journal.path(),
            format!("{}:0:0 {}\n", "11".repeat(32), "33".repeat(32)),
        )
        .unwrap();
        let snapshot = journal.load_or_migrate().unwrap();
        let notes = [preview_note(1_000_000, 0x11), preview_note(2_000_000, 0x12)];
        let mixed = argos_core::sprout_sweep::classify_sprout_notes(&notes, &snapshot);
        let plan = sprout_preview_plan(&mixed)
            .unwrap()
            .expect("one executable note");
        assert_eq!(plan.notes, 1);
        assert_eq!(plan.gross_zatoshis, 2_000_000);

        let huge = [preview_note(u64::MAX, 0x13), preview_note(u64::MAX, 0x14)];
        let huge_inventory = argos_core::sprout_sweep::classify_sprout_notes(&huge, &empty);
        let plan = sprout_preview_plan(&huge_inventory)
            .expect("overflow-safe preview")
            .expect("executable notes");
        assert_eq!(plan.gross_zatoshis, u64::MAX);
    }

    #[test]
    fn post_execution_reporting_never_attributes_a_historical_destination() {
        use argos_core::sprout_sweep::{SproutSweepOutcome, SproutSweepTransaction};

        let historical = SproutSweepOutcome {
            transactions: vec![SproutSweepTransaction {
                txid: "historical".to_owned(),
                value_zatoshis: Some(7),
                state: argos_core::TxLifecycleState::Pending,
                mined_height: None,
            }],
            ..Default::default()
        };
        let line = sprout_post_execution_pool_line(&historical).expect("pool line");
        assert!(line.contains("Sapling"), "{line}");
        assert!(
            !line.contains("unified") && !line.contains("address"),
            "{line}"
        );

        assert_eq!(sprout_post_execution_pool_line(&historical), Some(line));

        let source = include_str!("main.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(!source.contains("Canonically mined {} to {destination}"));
        assert_eq!(
            source
                .matches("Canonically mined {} from Sprout into Sapling.")
                .count(),
            2,
            "wallet and saved-scan execution must use the same provenance-safe summary"
        );
    }

    #[test]
    fn transparent_review_shows_exact_fee_and_net_before_confirmation() {
        let plan = argos_core::transparent_recovery::TransparentSweepPlan {
            input_count: 1,
            total_input_zatoshis: 250_000,
            fee_zatoshis: 15_000,
            output_zatoshis: 235_000,
        };
        let review = transparent_sweep_review(&plan, "zs1destination");
        assert!(
            review.contains("Gross              0.00250000 ZEC"),
            "{review}"
        );
        assert!(
            review.contains("Fee                0.00015000 ZEC"),
            "{review}"
        );
        assert!(
            review.contains("Net to destination 0.00235000 ZEC"),
            "{review}"
        );
        assert!(
            review.contains("Destination        zs1destination"),
            "{review}"
        );
    }

    #[test]
    fn orphan_nonterminal_journal_blocks_nothing_left_verdict() {
        let dir = tempfile::tempdir().unwrap();
        let journal = argos_core::sprout_sweep::SweepJournal::for_keys(
            dir.path(),
            &[[0x42; 32]],
            ZeckNetwork::Mainnet,
        );
        std::fs::write(
            journal.path(),
            format!("{}:0:0 {}\n", "11".repeat(32), "22".repeat(32)),
        )
        .unwrap();
        let snapshot = journal.load_or_migrate().unwrap();
        let recovered = argos_core::sprout_recovery::SproutRecovery {
            dust: vec![argos_core::argos_wallet_import::keys::JsOutPoint {
                txid: [0x33; 32],
                js_index: 0,
                output_index: 0,
            }],
            ..Default::default()
        };
        let inventory =
            argos_core::sprout_sweep::classify_sprout_notes(&recovered.notes, &snapshot);
        assert!(recovered.nothing_left_to_sweep(&inventory));
        assert!(!sprout_nothing_left(
            &recovered, &inventory, &snapshot, true
        ));

        for state in [
            argos_core::TxLifecycleState::Expired,
            argos_core::TxLifecycleState::Rejected,
        ] {
            assert!(lifecycle_snapshot_requires_source([state].into_iter()));
            assert!(!journal_states_allow_nothing_left([state].into_iter()));
        }
    }

    #[test]
    fn terminal_orphan_inspection_keeps_source_and_requires_recovery() {
        for state in [
            argos_core::TxLifecycleState::Expired,
            argos_core::TxLifecycleState::Rejected,
        ] {
            let guidance = sprout_lifecycle_status_guidance([state].into_iter())
                .expect("every journal row needs lifecycle guidance");
            assert!(guidance.contains("Keep the original wallet or Sprout key"));
            assert!(guidance.contains("rescan") || guidance.contains("recover"));
            assert!(!guidance.contains("no scan needed"), "{guidance}");
            assert!(!guidance.contains("To move them"), "{guidance}");
        }
    }

    #[test]
    fn terminal_only_sweep_and_scan_require_recovery_before_a_new_plan() {
        use argos_core::TxLifecycleState::{Expired, Pending, Rejected};

        for state in [Expired, Rejected] {
            assert_eq!(
                sprout_no_ready_action(false, [state].into_iter()),
                Some(SproutNoReadyAction::RecoverOrRescan),
            );
            let guidance = sprout_lifecycle_status_guidance([state].into_iter()).unwrap();
            assert!(guidance.contains("Recover or rescan"), "{guidance}");
            assert!(!guidance.contains("active journal"), "{guidance}");
            assert!(!guidance.contains("confirm-sweep"), "{guidance}");
        }

        assert_eq!(
            sprout_no_ready_action(false, [Pending].into_iter()),
            Some(SproutNoReadyAction::Reconcile),
        );
        assert_eq!(
            sprout_no_ready_action(true, [Expired].into_iter()),
            None,
            "a recovered expired note is ready to rebuild"
        );
    }

    #[test]
    fn reconcilable_zero_note_scan_offers_exact_byte_retry_not_a_new_sweep() {
        for destination_present in [false, true] {
            let guidance = sprout_scan_followup_guidance(
                Some(SproutNoReadyAction::Reconcile),
                destination_present,
            )
            .join(" ");
            assert!(
                guidance.contains("reconcile the existing journal"),
                "{guidance}"
            );
            assert!(guidance.contains("exact-byte retry"), "{guidance}");
            assert!(!guidance.contains("move these funds"), "{guidance}");
            assert!(!guidance.contains("broadcast the sweep"), "{guidance}");
            assert!(!guidance.contains("new proof"), "{guidance}");
        }
    }

    #[test]
    fn unreadable_journal_and_unconfirmed_scan_tip_block_final_verdicts() {
        let recovered = argos_core::sprout_recovery::SproutRecovery {
            dust: vec![argos_core::argos_wallet_import::keys::JsOutPoint {
                txid: [0x44; 32],
                js_index: 0,
                output_index: 0,
            }],
            ..Default::default()
        };
        let snapshot = argos_core::sprout_sweep::SproutJournalSnapshot::default();
        let inventory =
            argos_core::sprout_sweep::classify_sprout_notes(&recovered.notes, &snapshot);
        assert!(!sprout_nothing_left(
            &recovered, &inventory, &snapshot, false
        ));

        let mut outcome = argos_core::sprout_sweep::SproutSweepOutcome {
            fresh_all_mined: true,
            ..Default::default()
        };
        apply_sprout_tip_warning(&mut outcome, Some("tip coverage is incomplete".to_owned()));
        assert!(!outcome.fresh_all_mined);
        assert_eq!(outcome.warnings, vec!["tip coverage is incomplete"]);

        let err = anyhow::anyhow!("directory sync failed");
        apply_checkpoint_cleanup_error(&mut outcome, &err);
        assert!(!outcome.fresh_all_mined);
        assert!(outcome.warnings.iter().any(|warning| {
            warning.contains("Checkpoint cleanup failed")
                && warning.contains("directory sync failed")
        }));
    }

    #[test]
    fn omitted_transparent_max_fee_caps_submission_at_reviewed_fee() {
        let plan = argos_core::transparent_recovery::TransparentSweepPlan {
            input_count: 1,
            total_input_zatoshis: 250_000,
            fee_zatoshis: 15_000,
            output_zatoshis: 235_000,
        };
        assert_eq!(transparent_sweep_fee_cap(None, &plan), 15_000);
        assert_eq!(transparent_sweep_fee_cap(Some(12_000), &plan), 12_000);
    }

    #[test]
    fn reconcile_parses_txid_and_requires_it_for_explicit_resubmit() {
        let cli = Cli::try_parse_from([
            "argos",
            "reconcile",
            "--txid",
            "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
            "--resubmit",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Reconcile {
                txid: Some(_),
                resubmit: true
            }
        ));
        assert!(Cli::try_parse_from(["argos", "reconcile", "--resubmit"]).is_err());
    }

    #[test]
    fn ordinary_sweep_status_copy_preserves_uncertain_and_mined_boundaries() {
        use argos_core::TxLifecycleState as State;
        assert_eq!(sweep_status_label(State::NotSubmitted), "Not submitted.");
        assert_eq!(
            sweep_status_label(State::SubmissionUnknown),
            "Submission uncertain — may already be on the network. Do not retry."
        );
        assert_eq!(
            sweep_status_label(State::Pending),
            "Broadcast — awaiting independent confirmation."
        );
        assert_eq!(
            sweep_status_label(State::Mined),
            "Mined — independently confirmed."
        );
        assert_eq!(
            sweep_status_label(State::Expired),
            "Expired — rescan before rebuilding."
        );
        assert_eq!(sweep_status_label(State::Rejected), "Rejected by the node.");
        assert!(
            sweep_completion_guidance(&[State::SubmissionUnknown], false)
                .contains("Keep the source wallet")
        );
        assert!(
            sweep_completion_guidance(&[State::Pending], false).contains("Keep the source wallet")
        );
        assert!(
            !sweep_completion_guidance(&[State::Mined, State::Pending], false)
                .contains("Sweep complete")
        );
        assert!(!sweep_completion_guidance(&[State::Mined], true).contains("Sweep complete"));
        assert!(sweep_completion_guidance(&[State::Mined], false).contains("Sweep complete"));
        assert!(
            sweep_completion_guidance(&[State::SubmissionUnknown], true).contains("Do not retry")
        );
        assert!(
            sweep_completion_guidance(&[State::Mined, State::NotSubmitted], false)
                .contains("mined, but")
        );
    }

    #[test]
    fn ordinary_sweep_donation_and_completion_wait_for_certain_receipts() {
        use argos_core::TxLifecycleState as State;
        let uncertain = sweep_donation_line(Some(0.1), 0, &[State::SubmissionUnknown], None)
            .expect("requested donation must have a status line");
        assert!(uncertain.contains("Donation status and amount are uncertain"));
        assert!(!uncertain.contains("Donated") && !uncertain.contains("No donation"));
        let sent = sweep_donation_line(Some(0.1), 0, &[State::Mined], None).unwrap();
        assert!(sent.contains("No donation was sent"));
        assert!(sweep_donation_line(None, 0, &[State::Mined], None).is_none());

        let skipped = sweep_completion_guidance_with_skips(&[State::Mined], true, false);
        assert!(!skipped.contains("Sweep complete"));
        assert!(skipped.contains("not swept"));
        assert!(
            sweep_completion_guidance_with_skips(&[State::Mined], false, false)
                .contains("Sweep complete")
        );
    }

    #[test]
    fn donation_receipt_waits_for_mining_and_mixed_statuses_need_distinct_actions() {
        use argos_core::TxLifecycleState as State;
        let pending = sweep_donation_line(Some(0.1), 100_000, &[State::Pending], None).unwrap();
        assert!(pending
            .to_lowercase()
            .contains("awaiting independent confirmation"));
        assert!(!pending.contains("Donated"));
        let expired = sweep_donation_line(Some(0.1), 100_000, &[State::Expired], None).unwrap();
        assert!(expired.contains("not confirmed"));
        assert!(expired.contains("rescan"));
        assert!(!expired.contains("Donated"));
        let zero_pending = sweep_donation_line(Some(0.1), 0, &[State::Pending], None).unwrap();
        assert!(!zero_pending.contains("No donation was sent"));
        let rejected = sweep_donation_line(Some(0.1), 100_000, &[State::Rejected], None).unwrap();
        assert!(rejected.contains("No donation was sent or confirmed"));
        let mined = sweep_donation_line(Some(0.1), 100_000, &[State::Mined], None).unwrap();
        assert!(mined.contains("Donated to the Argos project"));

        for states in [
            vec![State::Pending, State::Expired],
            vec![State::SubmissionUnknown, State::Expired],
        ] {
            for follow_up in [false, true] {
                let guidance = sweep_completion_guidance(&states, follow_up);
                assert!(guidance.contains("rescan"), "{guidance}");
                assert!(guidance.to_lowercase().contains("reconcile"), "{guidance}");
                assert!(
                    !guidance.contains("every submitted transaction mines"),
                    "{guidance}"
                );
            }
        }
    }

    #[tokio::test]
    async fn empty_transparent_scan_reports_prior_blocking_txid() {
        use argos_core::broadcast::{BroadcastStore, PreparedTransaction, SubmissionDisposition};
        use zcash_primitives::transaction::TxId;
        let dir = tempfile::tempdir().unwrap();
        let txid = TxId::from_bytes([9; 32]);
        let registry =
            argos_core::service::NetworkOperationGuard::acquire(dir.path(), ZeckNetwork::Mainnet)
                .unwrap();
        let mut log = registry.open_broadcast_log().unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![1],
            fee_zatoshis: 10_000,
            expiry_height: None,
        })
        .unwrap();
        log.transition(
            txid,
            argos_core::TxLifecycleState::SubmissionUnknown,
            Some(&SubmissionDisposition::AmbiguousTransport),
            None,
        )
        .unwrap();
        drop(log);
        drop(registry);
        let error = run_transparent_sweep(
            &[],
            dir.path(),
            ZeckNetwork::Mainnet,
            "http://127.0.0.1:1",
            "irrelevant",
            None,
            false,
            true,
        )
        .await
        .expect_err("a zero scan cannot hide a prior uncertain submission");
        assert!(error.to_string().contains(&txid.to_string()), "{error}");
        assert!(error.to_string().contains("reconcile"), "{error}");
    }

    #[tokio::test]
    async fn unsent_prepared_transaction_blocks_a_new_cli_sweep_before_network() {
        use argos_core::broadcast::{BroadcastStore, PreparedTransaction};
        use zcash_primitives::transaction::TxId;

        let dir = tempfile::tempdir().unwrap();
        let registry =
            argos_core::service::NetworkOperationGuard::acquire(dir.path(), ZeckNetwork::Mainnet)
                .unwrap();
        let mut log = registry.open_broadcast_log().unwrap();
        let txid = TxId::from_bytes([0xC1; 32]);
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![1],
            fee_zatoshis: 15_000,
            expiry_height: None,
        })
        .unwrap();
        drop(log);
        drop(registry);

        let error = tokio::time::timeout(
            Duration::from_secs(2),
            run_transparent_sweep(
                &[],
                dir.path(),
                ZeckNetwork::Mainnet,
                "http://127.0.0.1:1",
                "irrelevant",
                None,
                false,
                true,
            ),
        )
        .await
        .expect("unresolved prepared bytes must block before lightwalletd")
        .expect_err("a new sweep cannot supersede prepared bytes");
        assert!(error.to_string().contains(&txid.to_string()), "{error}");
    }

    #[tokio::test]
    async fn overlapping_transparent_key_set_cannot_bypass_unresolved_submission() {
        use argos_core::argos_wallet_import::keys::{Provenance, TransparentKey};
        use argos_core::broadcast::{BroadcastStore, PreparedTransaction, SubmissionDisposition};
        use secrecy::Secret;
        use zcash_primitives::transaction::TxId;

        let dir = tempfile::tempdir().unwrap();
        let make_keys = |include_second: bool| {
            let mut imported = ImportedKeys::default();
            imported.transparent.push(TransparentKey {
                secret: Secret::new([1; 32]),
                provenance: Provenance::Standalone,
                created_at: None,
            });
            if include_second {
                imported.transparent.push(TransparentKey {
                    secret: Secret::new([2; 32]),
                    provenance: Provenance::Standalone,
                    created_at: None,
                });
            }
            imported_transparent_keys(&imported).unwrap()
        };
        let first_keys = make_keys(false);
        let overlapping_keys = make_keys(true);
        let txid = TxId::from_bytes([0xA5; 32]);
        let legacy = argos_core::transparent_recovery::standalone_broadcast_log_path(
            dir.path(),
            &first_keys,
            ZeckNetwork::Testnet,
        );
        std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        let mut log = argos_core::broadcast::DurableBroadcastLog::open(legacy).unwrap();
        log.persist_prepared(&PreparedTransaction {
            txid,
            raw_tx: vec![0x01],
            fee_zatoshis: 15_000,
            expiry_height: None,
        })
        .unwrap();
        log.transition(
            txid,
            argos_core::TxLifecycleState::SubmissionUnknown,
            Some(&SubmissionDisposition::AmbiguousTransport),
            None,
        )
        .unwrap();
        drop(log);

        let error = tokio::time::timeout(
            Duration::from_secs(2),
            run_transparent_sweep(
                &overlapping_keys,
                dir.path(),
                ZeckNetwork::Testnet,
                "http://127.0.0.1:1",
                "irrelevant",
                None,
                false,
                true,
            ),
        )
        .await
        .expect("unresolved submission must block before contacting lightwalletd")
        .expect_err("overlapping keys must not start a second sweep");
        assert!(error.to_string().contains(&txid.to_string()), "{error}");
    }

    #[tokio::test]
    async fn absent_standalone_legacy_journal_lock_blocks_cli_before_network() {
        use argos_core::argos_wallet_import::keys::{Provenance, TransparentKey};
        use secrecy::Secret;

        let dir = tempfile::tempdir().unwrap();
        let mut imported = ImportedKeys::default();
        imported.transparent.push(TransparentKey {
            secret: Secret::new([0x41; 32]),
            provenance: Provenance::Standalone,
            created_at: None,
        });
        let keys = imported_transparent_keys(&imported).unwrap();
        let legacy_path = argos_core::transparent_recovery::standalone_broadcast_log_path(
            dir.path(),
            &keys,
            ZeckNetwork::Testnet,
        );
        std::fs::create_dir_all(legacy_path.parent().unwrap()).unwrap();
        let legacy_writer = argos_core::broadcast::DurableBroadcastLog::open(&legacy_path).unwrap();
        assert!(!legacy_path.exists(), "only the old lock sidecar exists");

        let error = tokio::time::timeout(
            Duration::from_secs(2),
            run_transparent_sweep(
                &keys,
                dir.path(),
                ZeckNetwork::Testnet,
                "http://127.0.0.1:1",
                "irrelevant",
                None,
                false,
                true,
            ),
        )
        .await
        .expect("legacy lock must be checked before the network")
        .expect_err("an older writer may still submit from this standalone key set");
        assert!(error.to_string().contains("in use"), "{error}");
        drop(legacy_writer);
    }

    /// The speed-for-memory knob reaches the scanner.
    #[test]
    fn scan_batch_size_is_a_global_flag() {
        let cli = Cli::try_parse_from(["argos", "--scan-batch-size", "200", "scan"]).unwrap();
        assert_eq!(cli.scan_batch_size, Some(200));
        let cli = Cli::try_parse_from(["argos", "scan", "--scan-batch-size", "100"]).unwrap();
        assert_eq!(
            cli.scan_batch_size,
            Some(100),
            "global: accepted after the subcommand too"
        );
        let cli = Cli::try_parse_from(["argos", "scan"]).unwrap();
        assert_eq!(cli.scan_batch_size, None, "unset keeps the default");
    }

    #[test]
    fn confirmation_source_is_repeatable_and_global() {
        let cli = Cli::try_parse_from([
            "argos",
            "scan",
            "--confirmation-source",
            "one=https://one.example",
            "--confirmation-source",
            "two=https://two.example",
        ])
        .unwrap();
        let raw = cli
            .confirmation_source
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let sources = argos_core::lightwalletd::parse_confirmation_sources(&raw).unwrap();
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].operator_id, "one");
        assert_eq!(sources[1].operator_id, "two");
        let before = Cli::try_parse_from([
            "argos",
            "--confirmation-source",
            "one=https://one.example",
            "scan",
        ])
        .unwrap();
        assert_eq!(before.confirmation_source, vec!["one=https://one.example"]);
        let mixed = parse_cli_from([
            "argos",
            "--confirmation-source=one=https://one.example",
            "scan",
            "--confirmation-source",
            "two=https://two.example",
        ])
        .unwrap();
        assert_eq!(
            mixed.confirmation_source,
            vec!["one=https://one.example", "two=https://two.example",]
        );
    }

    /// A scan whose stdout went to a file or a pipe must still say on the
    /// terminal that it finished, what it found, and where the rest went. A
    /// user ran a 149-minute scan with stdout redirected, saw nothing, and
    /// asked whether that meant no funds.
    #[test]
    fn a_finished_scan_says_so_on_stderr_when_stdout_is_elsewhere() {
        let line = scan_summary_line(ScanPhase::Complete, &[150_000_000, 0, 25_000_000], None);
        assert!(line.contains("finished"), "{line}");
        assert!(line.contains("3 account(s)"), "{line}");
        assert!(line.contains("1.75000000 ZEC"), "{line}");
        assert!(line.contains("stdout"), "{line}");

        let nothing = scan_summary_line(ScanPhase::Complete, &[0, 0], None);
        assert!(
            nothing.contains("0 ZEC"),
            "a zero total is said, not left to silence: {nothing}"
        );

        let failed = scan_summary_line(ScanPhase::Error, &[], Some("lightwalletd unreachable"));
        assert!(
            failed.contains("did not finish") && failed.contains("lightwalletd unreachable"),
            "{failed}"
        );

        let cancelled = scan_summary_line(ScanPhase::Cancelled, &[], None);
        assert!(cancelled.contains("cancelled"), "{cancelled}");
    }

    /// On a terminal the full result is already on screen; the summary
    /// would only repeat it.
    #[test]
    fn the_summary_is_only_echoed_when_stdout_is_not_a_terminal() {
        assert!(echo_scan_summary(false));
        assert!(!echo_scan_summary(true));
    }

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

    fn fixture_keys(name: &str) -> ImportedKeys {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../argos-wallet-import/tests/fixtures")
            .join(name);
        let bytes = fs::read(&path).expect("fixture reads");
        argos_wallet_import::import_wallet_file(&bytes, None).expect("fixture parses")
    }

    /// The skip comes from the wallet's dated Sprout keys and nothing else;
    /// a key from --sprout-key-file, testnet, or the opt-outs remove it.
    #[test]
    fn the_sprout_skip_follows_the_wallets_own_key_times() {
        // Fixed, and later than the fixtures' 2026 key times.
        const NOW: i64 = 1_900_000_000;
        let wallet = fixture_keys("sprout-plaintext.dat");
        assert!(!wallet.sprout.is_empty(), "fixture holds a Sprout key");

        let plan = sprout_scan_plan(Some(&wallet), &[], ZeckNetwork::Mainnet, None, false, NOW);
        let skip = plan.decrypt_from.expect("a dated mainnet wallet skips");
        assert!(skip > 1, "{skip}");

        // The same key repeated in a key file changes nothing.
        let own = [*secrecy::ExposeSecret::expose_secret(
            &wallet.sprout[0].a_sk,
        )];
        let plan = sprout_scan_plan(Some(&wallet), &own, ZeckNetwork::Mainnet, None, false, NOW);
        assert_eq!(plan.decrypt_from, Some(skip));

        // A key the file cannot date means decrypting everything.
        let plan = sprout_scan_plan(
            Some(&wallet),
            &[[9u8; 32]],
            ZeckNetwork::Mainnet,
            None,
            false,
            NOW,
        );
        assert_eq!(plan.decrypt_from, None, "{}", plan.line);
        let plan = sprout_scan_plan(None, &[[9u8; 32]], ZeckNetwork::Mainnet, None, false, NOW);
        assert_eq!(plan.decrypt_from, None, "{}", plan.line);

        let plan = sprout_scan_plan(Some(&wallet), &[], ZeckNetwork::Testnet, None, false, NOW);
        assert_eq!(plan.decrypt_from, None, "{}", plan.line);

        let plan = sprout_scan_plan(Some(&wallet), &[], ZeckNetwork::Mainnet, None, true, NOW);
        assert_eq!(plan.decrypt_from, None);
        let plan = sprout_scan_plan(
            Some(&wallet),
            &[],
            ZeckNetwork::Mainnet,
            Some(1_000),
            false,
            NOW,
        );
        assert_eq!(plan.decrypt_from, Some(1_000));
        let plan = sprout_scan_plan(
            Some(&wallet),
            &[],
            ZeckNetwork::Mainnet,
            Some(skip + 1),
            false,
            NOW,
        );
        assert_eq!(
            plan.decrypt_from,
            Some(skip),
            "a later birthday never raises it"
        );
    }

    /// --birthday has no clap default, so an explicit value can be told
    /// apart from none -- the Sprout scan must not treat 419200 it never
    /// saw as a request to decrypt from there.
    #[test]
    fn an_explicit_birthday_is_distinguishable_from_the_default() {
        let cli = Cli::try_parse_from(["argos", "scan"]).unwrap();
        assert_eq!(cli.birthday, None);
        assert_eq!(cli.birthday_or_default(), 419_200);
        let cli = Cli::try_parse_from(["argos", "--network", "testnet", "scan"]).unwrap();
        assert_eq!(cli.birthday_or_default(), 280_000);
        let cli = Cli::try_parse_from(["argos", "scan-sprout", "--birthday", "5"]).unwrap();
        assert_eq!(cli.birthday, Some(5));
        assert_eq!(cli.birthday_or_default(), 5);
        let cli = Cli::try_parse_from(["argos", "scan-sprout", "--no-birthday-skip"]).unwrap();
        assert!(cli.no_birthday_skip);
    }

    #[test]
    fn show_keys_does_not_use_birthday_or_network_probe_inputs() {
        let cli = Cli::try_parse_from([
            "argos",
            "--birthday-auto-detect",
            "--lightwalletd-url",
            "https://example.invalid:443",
            "show-keys",
        ])
        .expect("show-keys should accept global scan flags for compatibility");

        assert!(
            !command_uses_birthday_inputs(&cli.command),
            "show-keys must stay purely local even when global birthday flags are present"
        );
    }

    /// The Sprout hints print `argos scan-sprout --wallet-file …` and
    /// `argos sweep-sprout --wallet-file …` as the literal next command.
    /// A user copies those verbatim, so the flags must parse after the
    /// subcommand as well as before it.
    #[test]
    fn key_source_flags_are_accepted_after_the_subcommand() {
        let cli = Cli::try_parse_from([
            "argos",
            "scan-sprout",
            "--wallet-file",
            "wallet.dat",
            "--destination",
            "zs1example",
        ])
        .expect("the scan-sprout hint must parse as printed");
        assert_eq!(cli.wallet_file, Some(PathBuf::from("wallet.dat")));

        let cli = Cli::try_parse_from([
            "argos",
            "sweep-sprout",
            "--wallet-file",
            "wallet.dat",
            "--destination",
            "zs1example",
            "--confirm-sweep",
        ])
        .expect("the sweep-sprout hint must parse as printed");
        assert_eq!(cli.wallet_file, Some(PathBuf::from("wallet.dat")));

        let cli = Cli::try_parse_from([
            "argos",
            "scan",
            "--seed-file",
            "seed.txt",
            "--network",
            "testnet",
            "--data-dir",
            "d",
            "--accept-tos",
        ])
        .expect("top-level flags must be accepted after any subcommand");
        assert_eq!(cli.seed_file, Some(PathBuf::from("seed.txt")));
        assert!(cli.accept_tos);
    }

    #[test]
    fn global_flag_conflicts_still_apply_after_the_subcommand() {
        let err = Cli::try_parse_from([
            "argos",
            "scan",
            "--seed-file",
            "seed.txt",
            "--wallet-file",
            "wallet.dat",
        ])
        .expect_err("--seed-file and --wallet-file must still conflict");
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
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
        assert_eq!(
            format_eta_range(3 * 3600 + 1800),
            "about 3-4 hours remaining"
        );
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
        let progress = make_progress(ScanPhase::Complete, &[(0, 100_000_000), (3, 50_000_000)]);
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

    fn make_progress(phase: ScanPhase, funded: &[(u32, u64)]) -> argos_core::ScanProgress {
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
            gap_extension: None,
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
