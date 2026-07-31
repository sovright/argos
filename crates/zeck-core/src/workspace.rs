use std::{
    fs,
    path::{Path, PathBuf},
};

use rand_core::OsRng;
use secrecy::{SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zcash_client_backend::data_api::{wallet::ConfirmationsPolicy, WalletRead};
use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, WalletDb};
use zcash_protocol::consensus::{BlockHeight, Network, NetworkType, NetworkUpgrade, Parameters};
#[cfg(feature = "argos-network")]
use zcash_protocol::local_consensus::LocalNetwork;

use crate::{
    error::{ZeckError, ZeckResult},
    key_source::{KeySource, SeedKeySource},
    models::{RuntimeScanConfig, ZeckNetwork},
};

/// Filename for the per-workspace session metadata sidecar. Lives next to
/// `wallet.sqlite` inside the workspace root.
pub const SESSION_FILE_NAME: &str = "session.json";

/// Current sidecar schema. Bumped whenever fields are added or semantics
/// change so older readers can refuse rather than silently misinterpret.
const SESSION_SCHEMA_VERSION: u32 = 1;

/// On-disk location of a wallet workspace for one (network, seed, birthday,
/// gap-strategy) tuple.
///
/// Resume keying: identical scan args MUST resolve to the same `root`
/// across runs. This module's tests pin that contract. The downstream
/// behavior — that re-running Argos with the same args actually resumes
/// from `WalletSummary::fully_scanned_height` — depends on `WalletDb`
/// and `BlockDb` initializers being idempotent against existing on-disk
/// workspaces, which is an upstream contract from `zcash_client_sqlite`.
/// That contract is not pinned here; treat it as a thing to verify
/// during dependency bumps.
///
/// Privacy: the per-wallet path component is a SHA-256-derived hash of
/// `(domain, network, seed-fingerprint, birthday, scope)` rather than the
/// literal seed fingerprint string. An attacker with the seed can still
/// recompute the path, but local filesystem inspection no longer surfaces
/// the bech32 fingerprint directly.
#[derive(Debug, Clone)]
pub struct RecoveryWorkspace {
    root: PathBuf,
    /// First path component under `data_dir/<network>` that is private to
    /// this wallet — used to tighten permissions without touching the
    /// generic data_dir or network directories above it.
    private_root: PathBuf,
    wallet_db_path: PathBuf,
}

impl RecoveryWorkspace {
    pub fn from_runtime(config: &RuntimeScanConfig) -> ZeckResult<Self> {
        let source = SeedKeySource::new(config.seed_phrase.clone());
        Self::from_key_source(&source, config)
    }

    /// Build a workspace from any key source.
    ///
    /// `from_runtime` remains as a thin wrapper so existing seed callers
    /// and their on-disk workspaces are untouched. For a seed source this
    /// must produce byte-identical paths to the old implementation, or
    /// every in-progress scan on disk is orphaned.
    pub fn from_key_source(source: &dyn KeySource, config: &RuntimeScanConfig) -> ZeckResult<Self> {
        let path_component = source.workspace_path_component()?;

        let scope = match config.num_accounts {
            Some(num_accounts) => format!("accounts-{num_accounts}"),
            None => format!("auto-gap-{}", config.gap_limit),
        };

        let workspace_id =
            derive_workspace_id(config.network, &path_component, config.birthday, &scope);
        let private_root = config
            .data_dir
            .join(config.network.label())
            .join(format!("workspace-{workspace_id}"));
        let root = private_root
            .join(format!("birthday-{}", config.birthday))
            .join(&scope);

        Ok(Self {
            wallet_db_path: root.join("wallet.sqlite"),
            root,
            private_root,
        })
    }

    pub fn initialize(&self, network: ZeckNetwork, seed: &[u8; 64]) -> ZeckResult<()> {
        create_private_dir_all(&self.root)?;
        // recursive create only sets mode on newly-created dirs; explicitly
        // re-tighten every component from the wallet-private root down so
        // resumes don't quietly inherit looser perms set in a previous run.
        tighten_private_perms(&self.private_root, &self.root)?;

        let mut wallet_db = open_wallet_db(&self.wallet_db_path, consensus_network(network))?;
        init_wallet_db(&mut wallet_db, Some(SecretVec::new(seed.to_vec()))).map_err(|err| {
            ZeckError::Wallet(format!(
                "initializing wallet database {}: {err}",
                self.wallet_db_path.display()
            ))
        })?;
        set_private_file_permissions(&self.wallet_db_path)?;
        // WAL mode adds `-wal`/`-shm` sidecar files; tighten them too.
        // Best-effort: SQLite recreates them with the DB file's permissions otherwise.
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = self.wallet_db_path.as_os_str().to_owned();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            if sidecar.exists() {
                set_private_file_permissions(&sidecar)?;
            }
        }

        Ok(())
    }

    /// Build the wallet database for any key source. Imported key sets
    /// have no seed, so `init_wallet_db` receives `None` for them.
    pub fn initialize_from_source(
        &self,
        network: ZeckNetwork,
        source: &dyn KeySource,
    ) -> ZeckResult<()> {
        create_private_dir_all(&self.root)?;
        tighten_private_perms(&self.private_root, &self.root)?;

        let mut wallet_db = open_wallet_db(&self.wallet_db_path, consensus_network(network))?;
        let seed = source.wallet_seed()?.map(|s| SecretVec::new(s.to_vec()));
        init_wallet_db(&mut wallet_db, seed).map_err(|err| {
            ZeckError::Wallet(format!(
                "initializing wallet database {}: {err}",
                self.wallet_db_path.display()
            ))
        })?;
        set_private_file_permissions(&self.wallet_db_path)?;
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = self.wallet_db_path.as_os_str().to_owned();
            sidecar.push(suffix);
            let sidecar = PathBuf::from(sidecar);
            if sidecar.exists() {
                set_private_file_permissions(&sidecar)?;
            }
        }
        Ok(())
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn wallet_db_path(&self) -> &Path {
        &self.wallet_db_path
    }
}

/// The consensus parameter set Argos evaluates heights against.
///
/// Production builds only ever hold [`Network::MainNetwork`] or
/// [`Network::TestNetwork`]. The `argos-network` feature adds a regtest variant
/// so the integration harness can drive a private chain: a regtest chain is a
/// few hundred blocks tall, and under testnet activation heights (NU5 at
/// 1_842_420) every such height resolves to a pre-NU5 consensus branch. Scans
/// tolerate that, but a sweep would be signed with the wrong branch ID and
/// rejected by the node, so the harness cannot test sweeping without real
/// regtest parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgosParams {
    /// Mainnet or testnet — the only variants a released binary can construct.
    Consensus(Network),
    /// A private regtest chain's activation heights. Test builds only.
    #[cfg(feature = "argos-network")]
    Regtest(LocalNetwork),
}

/// Regtest activation heights with every upgrade through Ironwood active from
/// height 1, matching what the harness configures on Zebra in
/// `tests/regtest/zebrad-regtest.toml`. Genesis (height 0) is reserved, so 1
/// is the earliest an upgrade may activate. These two definitions must stay in
/// sync: Argos evaluates consensus branch IDs against this copy, and a
/// mismatch means sweeps are signed for a branch the node will reject.
#[cfg(feature = "argos-network")]
pub fn regtest_local_network() -> LocalNetwork {
    let h = Some(BlockHeight::from_u32(1));
    LocalNetwork {
        overwinter: h,
        sapling: h,
        blossom: h,
        heartwood: h,
        canopy: h,
        nu5: h,
        nu6: h,
        nu6_1: h,
        nu6_2: h,
        nu6_3: h,
    }
}

impl ArgosParams {
    /// [`regtest_local_network`] wrapped as an [`ArgosParams`].
    #[cfg(feature = "argos-network")]
    pub fn regtest_all_active() -> Self {
        let h = Some(BlockHeight::from_u32(1));
        Self::Regtest(LocalNetwork {
            overwinter: h,
            sapling: h,
            blossom: h,
            heartwood: h,
            canopy: h,
            nu5: h,
            nu6: h,
            nu6_1: h,
            nu6_2: h,
            nu6_3: h,
        })
    }
}

impl Parameters for ArgosParams {
    fn network_type(&self) -> NetworkType {
        match self {
            Self::Consensus(network) => network.network_type(),
            #[cfg(feature = "argos-network")]
            Self::Regtest(local) => local.network_type(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Self::Consensus(network) => network.activation_height(nu),
            #[cfg(feature = "argos-network")]
            Self::Regtest(local) => local.activation_height(nu),
        }
    }
}

/// Regtest override, installed once by the integration harness before any scan
/// or sweep runs. Compiled out entirely in production builds, so a released
/// binary has no code path that can retarget consensus parameters.
#[cfg(feature = "argos-network")]
static REGTEST_PARAMS: std::sync::OnceLock<LocalNetwork> = std::sync::OnceLock::new();

/// Point Argos at a private regtest chain's consensus rules for the remainder
/// of the process. Idempotent only in the sense that a second *differing* call
/// is an error: consensus parameters must not change under a running scan.
#[cfg(feature = "argos-network")]
pub fn set_regtest_consensus_params(params: LocalNetwork) -> ZeckResult<()> {
    match REGTEST_PARAMS.get() {
        Some(existing) if *existing == params => Ok(()),
        Some(_) => Err(ZeckError::Internal(
            "regtest consensus parameters were already set to a different value".to_owned(),
        )),
        None => {
            let _ = REGTEST_PARAMS.set(params);
            Ok(())
        }
    }
}

/// Whether [`set_regtest_consensus_params`] has been called in this process.
///
/// Used to gate the harness's relaxation of lightwalletd network validation.
/// This is a strictly stronger signal than the chain name the server reports:
/// it reflects a deliberate local act, so a hostile server cannot talk its way
/// into the relaxation by naming itself `regtest`.
#[cfg(feature = "argos-network")]
pub fn regtest_consensus_params_installed() -> bool {
    REGTEST_PARAMS.get().is_some()
}

pub fn consensus_network(network: ZeckNetwork) -> ArgosParams {
    #[cfg(feature = "argos-network")]
    if let Some(params) = REGTEST_PARAMS.get() {
        return ArgosParams::Regtest(*params);
    }
    match network {
        ZeckNetwork::Mainnet => ArgosParams::Consensus(Network::MainNetwork),
        ZeckNetwork::Testnet => ArgosParams::Consensus(Network::TestNetwork),
    }
}

fn derive_workspace_id(
    network: ZeckNetwork,
    path_component: &str,
    birthday: u32,
    scope: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"zeck-workspace-v1\0");
    hasher.update(network.label().as_bytes());
    hasher.update(b"\0");
    hasher.update(path_component.as_bytes());
    hasher.update(b"\0");
    hasher.update(birthday.to_le_bytes());
    hasher.update(b"\0");
    hasher.update(scope.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn create_private_dir_all(path: &Path) -> ZeckResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        // mode(0o700) only applies to dirs created during this call; pre-
        // existing parents keep their mode. We explicitly tighten the
        // wallet-private subtree separately via tighten_private_perms.
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|err| ZeckError::Storage(format!("creating {}: {err}", path.display())))?;
    }

    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
            .map_err(|err| ZeckError::Storage(format!("creating {}: {err}", path.display())))?;
    }

    Ok(())
}

#[allow(unused_variables)]
fn tighten_private_perms(private_root: &Path, leaf: &Path) -> ZeckResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut current = leaf.to_path_buf();
        loop {
            fs::set_permissions(&current, fs::Permissions::from_mode(0o700)).map_err(|err| {
                ZeckError::Storage(format!(
                    "setting private permissions on {}: {err}",
                    current.display()
                ))
            })?;
            if current == private_root {
                break;
            }
            match current.parent() {
                Some(parent) => current = parent.to_path_buf(),
                None => break,
            }
        }
    }

    Ok(())
}

fn set_private_file_permissions(path: &Path) -> ZeckResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|err| {
            ZeckError::Storage(format!(
                "setting private permissions on {}: {err}",
                path.display()
            ))
        })?;
    }

    #[cfg(not(unix))]
    {
        let _ = path;
    }

    Ok(())
}

/// Create (or truncate) `path` and write `bytes`, restricting the file to
/// `0o600` at creation time on Unix via `OpenOptions::mode`. This keeps
/// file-level protection in place independent of the parent directory's
/// mode (audit Suggestion 3). On non-Unix platforms there is no mode-bit
/// equivalent, so this degrades to a plain create-truncate write and the
/// `0o700` parent directory remains the sole protection.
fn write_private_file(path: &Path, bytes: &[u8]) -> ZeckResult<()> {
    use std::io::Write;

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options
        .open(path)
        .map_err(|err| ZeckError::Storage(format!("creating {}: {err}", path.display())))?;
    // `OpenOptions::mode` only constrains newly-created files. If this path
    // already existed with looser permissions, tighten it before writing fresh
    // sensitive contents into the truncated file.
    set_private_file_permissions(path)?;
    file.write_all(bytes)
        .map_err(|err| ZeckError::Storage(format!("writing {}: {err}", path.display())))?;

    // Keep the final mode tight even if a platform/filesystem changes metadata
    // during the write.
    set_private_file_permissions(path)?;

    Ok(())
}

/// Seconds a wallet-database connection waits on a locked database before
/// returning `SQLITE_BUSY`. The scan writer and the once-per-second progress
/// poller share the file, so lock collisions are routine rather than exceptional.
const WALLET_DB_BUSY_TIMEOUT_SECS: u64 = 5;

/// Opens a raw SQLite connection with the tuning Argos requires:
/// WAL journal mode, `synchronous=NORMAL`, and a busy timeout.
///
/// `zcash_client_sqlite` deliberately leaves connection tuning to the embedder;
/// its `WalletDb::for_path` opens with SQLite defaults (rollback journal,
/// `synchronous=FULL`, no busy timeout). All production opens of `wallet.sqlite`
/// should come through [`open_wallet_db`] instead.
fn open_tuned_wallet_connection(path: &Path) -> Result<rusqlite::Connection, rusqlite::Error> {
    let conn = rusqlite::Connection::open(path)?;
    // `WalletDb::from_connection` requires the array module to be loaded.
    rusqlite::vtab::array::load_module(&conn)?;
    conn.busy_timeout(std::time::Duration::from_secs(WALLET_DB_BUSY_TIMEOUT_SECS))?;
    // `PRAGMA journal_mode` returns the resulting mode as a row, so it needs
    // the query form rather than `pragma_update`.
    conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    Ok(conn)
}

/// Opens a wallet database with the connection tuning from
/// [`open_tuned_wallet_connection`]. All production opens of
/// `wallet.sqlite` should come through here.
/// Test-only accessor for [`open_wallet_db`].
///
/// The regtest funding helper has to drive `propose_shielding_coinbase` and
/// `propose_transfer` directly — Zebra has no wallet RPCs, and coinbase output
/// may not be spent to a transparent address, so funding the test seed cannot
/// go through Argos's own sweep. Compiled out of production builds.
#[cfg(feature = "argos-network")]
pub fn open_wallet_db_for_tests(
    path: &Path,
    network: ArgosParams,
) -> ZeckResult<WalletDb<rusqlite::Connection, ArgosParams, SystemClock, OsRng>> {
    open_wallet_db(path, network)
}

pub(crate) fn open_wallet_db(
    path: &Path,
    network: ArgosParams,
) -> ZeckResult<WalletDb<rusqlite::Connection, ArgosParams, SystemClock, OsRng>> {
    let conn = open_tuned_wallet_connection(path).map_err(|err| {
        ZeckError::Storage(format!("opening wallet database {}: {err}", path.display()))
    })?;
    Ok(WalletDb::from_connection(conn, network, SystemClock, OsRng))
}

/// On-disk metadata describing a scan session. Written next to the wallet
/// database when a scan starts and updated as it progresses. The launch-time
/// "resume an unfinished scan" UI keys on `completed == false`.
///
/// Contains nothing sensitive — no seed, no keys. Just enough for the user
/// to recognize their own scan and for the app to identify the workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionMetadata {
    pub schema_version: u32,
    pub label: String,
    pub network: ZeckNetwork,
    pub birthday: u32,
    /// Chain-tip height recorded at the start of the most recent run. `None`
    /// if the lightwalletd probe never succeeded for this run.
    pub target_height: Option<u32>,
    /// Unix epoch seconds of the most recent run (start or retry).
    pub last_run_at_epoch_seconds: i64,
    pub completed: bool,
}

impl SessionMetadata {
    pub fn new_in_progress(
        label: String,
        network: ZeckNetwork,
        birthday: u32,
        target_height: Option<u32>,
        now_epoch_seconds: i64,
    ) -> Self {
        Self {
            schema_version: SESSION_SCHEMA_VERSION,
            label,
            network,
            birthday,
            target_height,
            last_run_at_epoch_seconds: now_epoch_seconds,
            completed: false,
        }
    }
}

/// Row returned to callers listing incomplete sessions on disk. Mirrors
/// `SessionMetadata` plus the wallet's persisted scan progress, which is
/// readable without the seed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncompleteSession {
    pub workspace_path: PathBuf,
    pub label: String,
    pub network: ZeckNetwork,
    pub birthday: u32,
    pub synced_to_height: Option<u32>,
    pub target_height: Option<u32>,
    pub last_run_at_epoch_seconds: Option<i64>,
}

fn session_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join(SESSION_FILE_NAME)
}

/// Atomic write: write to `<path>.tmp` then rename. Best-effort guarantee
/// that a crash mid-write does not leave a half-written sidecar.
pub fn write_session_metadata(workspace_root: &Path, meta: &SessionMetadata) -> ZeckResult<()> {
    fs::create_dir_all(workspace_root).map_err(|err| {
        ZeckError::Storage(format!("creating {}: {err}", workspace_root.display()))
    })?;
    let final_path = session_path(workspace_root);
    let tmp_path = workspace_root.join(format!("{SESSION_FILE_NAME}.tmp"));
    let bytes =
        serde_json::to_vec_pretty(meta).map_err(|err| ZeckError::Serialization(err.to_string()))?;
    write_private_file(&tmp_path, &bytes)?;
    fs::rename(&tmp_path, &final_path).map_err(|err| {
        ZeckError::Storage(format!(
            "renaming {} -> {}: {err}",
            tmp_path.display(),
            final_path.display(),
        ))
    })?;
    Ok(())
}

/// Read the sidecar at `workspace_root/session.json`. Returns `Ok(None)` if
/// missing or unparseable; only filesystem errors other than "not found"
/// surface as `Err`. Treating corrupt sidecars as missing keeps the launch
/// list robust against a bad write — the workspace is still usable, just
/// shows up as legacy.
pub fn read_session_metadata(workspace_root: &Path) -> ZeckResult<Option<SessionMetadata>> {
    let path = session_path(workspace_root);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(ZeckError::Storage(format!(
                "reading {}: {err}",
                path.display()
            )));
        }
    };
    Ok(serde_json::from_slice::<SessionMetadata>(&bytes).ok())
}

/// Mark an existing in-progress session as completed. Idempotent: if the
/// sidecar is missing or unparseable, this is a no-op.
pub fn mark_session_completed(workspace_root: &Path, now_epoch_seconds: i64) -> ZeckResult<()> {
    let Some(mut meta) = read_session_metadata(workspace_root)? else {
        return Ok(());
    };
    meta.completed = true;
    meta.last_run_at_epoch_seconds = now_epoch_seconds;
    write_session_metadata(workspace_root, &meta)
}

/// Update `last_run_at` on an existing sidecar. Best-effort — any error is
/// returned to the caller, who is expected to swallow it on the hot path.
pub fn touch_session_last_run(workspace_root: &Path, now_epoch_seconds: i64) -> ZeckResult<()> {
    let Some(mut meta) = read_session_metadata(workspace_root)? else {
        return Ok(());
    };
    meta.last_run_at_epoch_seconds = now_epoch_seconds;
    write_session_metadata(workspace_root, &meta)
}

/// Walk `data_dir` and return any workspaces whose sidecar reports
/// `completed: false` or that have no readable sidecar (legacy). The latter
/// is treated as incomplete because we can't prove otherwise without the seed.
///
/// This function never opens a wallet for writing — the read-only summary
/// query does not need the seed.
pub fn list_incomplete_sessions(data_dir: &Path) -> ZeckResult<Vec<IncompleteSession>> {
    let mut rows = Vec::new();
    let networks = match fs::read_dir(data_dir) {
        Ok(rd) => rd,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(rows),
        Err(err) => {
            return Err(ZeckError::Storage(format!(
                "reading {}: {err}",
                data_dir.display()
            )));
        }
    };

    for network_entry in networks.flatten() {
        if !network_entry
            .file_type()
            .map(|t| t.is_dir())
            .unwrap_or(false)
        {
            continue;
        }
        let network_name = network_entry.file_name();
        let network = match network_name.to_str() {
            Some("mainnet") => ZeckNetwork::Mainnet,
            Some("testnet") => ZeckNetwork::Testnet,
            _ => continue,
        };
        let Ok(workspaces) = fs::read_dir(network_entry.path()) else {
            continue;
        };
        for workspace_entry in workspaces.flatten() {
            if !workspace_entry
                .file_type()
                .map(|t| t.is_dir())
                .unwrap_or(false)
            {
                continue;
            }
            // Per-wallet directory is named `workspace-<sha256>`. Skip
            // anything else so we don't try to read sibling files.
            if !workspace_entry
                .file_name()
                .to_str()
                .map(|s| s.starts_with("workspace-"))
                .unwrap_or(false)
            {
                continue;
            }
            let Ok(birthdays) = fs::read_dir(workspace_entry.path()) else {
                continue;
            };
            for birthday_entry in birthdays.flatten() {
                if !birthday_entry
                    .file_type()
                    .map(|t| t.is_dir())
                    .unwrap_or(false)
                {
                    continue;
                }
                let Some(birthday) = parse_birthday_segment(&birthday_entry.file_name()) else {
                    continue;
                };
                let Ok(scopes) = fs::read_dir(birthday_entry.path()) else {
                    continue;
                };
                for scope_entry in scopes.flatten() {
                    if !scope_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        continue;
                    }
                    let workspace_path = scope_entry.path();
                    if let Some(row) = try_build_incomplete_row(&workspace_path, network, birthday)
                    {
                        rows.push(row);
                    }
                }
            }
        }
    }

    // Newest first by last_run_at; legacy rows with no timestamp sort last.
    rows.sort_by(|a, b| {
        b.last_run_at_epoch_seconds
            .cmp(&a.last_run_at_epoch_seconds)
    });
    Ok(rows)
}

fn parse_birthday_segment(name: &std::ffi::OsStr) -> Option<u32> {
    let s = name.to_str()?;
    s.strip_prefix("birthday-")?.parse::<u32>().ok()
}

/// Build one row for the launch-time list. Returns `None` when the candidate
/// workspace is complete, or when the wallet database is missing/unreadable
/// (i.e. there is nothing to resume).
fn try_build_incomplete_row(
    workspace_path: &Path,
    network: ZeckNetwork,
    birthday: u32,
) -> Option<IncompleteSession> {
    let wallet_db_path = workspace_path.join("wallet.sqlite");
    if !wallet_db_path.exists() {
        return None;
    }

    let meta = read_session_metadata(workspace_path).ok().flatten();
    if meta.as_ref().map(|m| m.completed).unwrap_or(false) {
        return None;
    }

    let synced_to_height = read_synced_height(&wallet_db_path, network);

    let (label, target_height, last_run_at) = match meta {
        Some(m) => (m.label, m.target_height, Some(m.last_run_at_epoch_seconds)),
        None => ("(unlabeled scan)".to_owned(), None, None),
    };

    Some(IncompleteSession {
        workspace_path: workspace_path.to_owned(),
        label,
        network,
        birthday,
        synced_to_height,
        target_height,
        last_run_at_epoch_seconds: last_run_at,
    })
}

fn read_synced_height(wallet_db_path: &Path, network: ZeckNetwork) -> Option<u32> {
    let wallet_db = open_wallet_db(wallet_db_path, consensus_network(network)).ok()?;
    let summary = wallet_db
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .ok()
        .flatten()?;
    Some(u32::from(summary.fully_scanned_height()))
}

/// Re-derive the workspace id from `seed_phrase` plus the keying segments
/// in `workspace_path`, and verify it matches the path's `workspace-<id>`
/// segment. Used at resume time so a caller cannot unlock a workspace
/// with the wrong seed.
pub fn verify_seed_for_workspace(
    workspace_path: &Path,
    seed_phrase: &SecretString,
) -> ZeckResult<()> {
    let source = SeedKeySource::new(seed_phrase.clone());
    verify_key_source_for_workspace(workspace_path, &source)
}

/// Re-derive the workspace id from `source` plus the keying segments in
/// `workspace_path`, and verify it matches the path's `workspace-<id>`
/// segment. Used at resume time so a caller cannot unlock a workspace with
/// the wrong keys.
pub fn verify_key_source_for_workspace(
    workspace_path: &Path,
    source: &dyn KeySource,
) -> ZeckResult<()> {
    let path_id = extract_workspace_id_segment(workspace_path).ok_or_else(|| {
        ZeckError::InvalidConfig(format!(
            "workspace path {} does not contain a workspace-id segment",
            workspace_path.display()
        ))
    })?;
    let keying = parse_workspace_keying(workspace_path)?;
    let scope = scope_segment(&keying);

    let path_component = source.workspace_path_component()?;
    let expected_id = derive_workspace_id(keying.network, &path_component, keying.birthday, &scope);

    if expected_id != path_id {
        return Err(ZeckError::InvalidConfig(
            "this seed phrase does not match the selected scan".to_owned(),
        ));
    }
    Ok(())
}

fn scope_segment(keying: &WorkspaceKeying) -> String {
    match keying.num_accounts {
        Some(num_accounts) => format!("accounts-{num_accounts}"),
        None => format!("auto-gap-{}", keying.gap_limit),
    }
}

/// Layout: `<data_dir>/<network>/workspace-<id>/birthday-N/<scope>`. The
/// `workspace-<id>` segment is the great-great-grandparent of the workspace
/// root's `wallet.sqlite`. Returns just the `<id>` portion (without the
/// `workspace-` prefix) so the caller can compare against
/// `derive_workspace_id` output directly.
fn extract_workspace_id_segment(workspace_path: &Path) -> Option<String> {
    let components: Vec<&std::ffi::OsStr> = workspace_path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s),
            _ => None,
        })
        .collect();
    // Walk from the leaf back: scope, birthday-N, workspace-<id>, network.
    if components.len() < 4 {
        return None;
    }
    let len = components.len();
    let raw = components[len - 3].to_str()?;
    raw.strip_prefix("workspace-").map(|s| s.to_owned())
}

/// Reconstruct the runtime keying inputs (network, birthday, num_accounts,
/// gap_limit) from a workspace path. Used by the resume flow so the GUI
/// does not have to remember them across launches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceKeying {
    pub network: ZeckNetwork,
    pub birthday: u32,
    pub num_accounts: Option<u32>,
    pub gap_limit: u32,
}

pub fn parse_workspace_keying(workspace_path: &Path) -> ZeckResult<WorkspaceKeying> {
    let components: Vec<String> = workspace_path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => s.to_str().map(|s| s.to_owned()),
            _ => None,
        })
        .collect();
    if components.len() < 4 {
        return Err(ZeckError::InvalidConfig(format!(
            "workspace path {} is shorter than the expected layout",
            workspace_path.display()
        )));
    }
    let len = components.len();
    let scope = &components[len - 1];
    let birthday_seg = &components[len - 2];
    // fingerprint = components[len - 3]; we don't need it here.
    let network_seg = &components[len - 4];

    let network = match network_seg.as_str() {
        "mainnet" => ZeckNetwork::Mainnet,
        "testnet" => ZeckNetwork::Testnet,
        other => {
            return Err(ZeckError::InvalidConfig(format!(
                "unrecognized network segment {other:?}"
            )));
        }
    };
    let birthday = birthday_seg
        .strip_prefix("birthday-")
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| {
            ZeckError::InvalidConfig(format!("malformed birthday segment {birthday_seg:?}"))
        })?;

    // Two scope shapes: `auto-gap-N` (gap_limit driven) or `accounts-N`
    // (explicit num_accounts). These are exclusive; pick whichever matches.
    let (num_accounts, gap_limit) = if let Some(rest) = scope.strip_prefix("auto-gap-") {
        let gap = rest
            .parse::<u32>()
            .map_err(|_| ZeckError::InvalidConfig(format!("malformed scope segment {scope:?}")))?;
        (None, gap)
    } else if let Some(rest) = scope.strip_prefix("accounts-") {
        let count = rest
            .parse::<u32>()
            .map_err(|_| ZeckError::InvalidConfig(format!("malformed scope segment {scope:?}")))?;
        // gap_limit is unused when num_accounts is set, but the validator
        // still requires gap_limit >= 1; pick the same value as `count`
        // so it round-trips through the existing config pipeline cleanly.
        (Some(count), count.max(1))
    } else {
        return Err(ZeckError::InvalidConfig(format!(
            "unrecognized scope segment {scope:?}"
        )));
    };

    Ok(WorkspaceKeying {
        network,
        birthday,
        num_accounts,
        gap_limit,
    })
}

/// Regtest consensus behaviour (`argos-network` builds only).
///
/// These tests pin the reason `ArgosParams` exists: against a private regtest
/// chain a few hundred blocks tall, testnet activation heights resolve to a
/// pre-NU5 consensus branch, so a sweep would be signed with the wrong branch
/// ID and rejected. Regtest params must instead report Ironwood.
#[cfg(all(test, feature = "argos-network"))]
mod regtest_params_tests {
    use zcash_protocol::consensus::{
        BlockHeight, BranchId, NetworkType, NetworkUpgrade, Parameters,
    };

    use super::*;

    /// Every upgrade active from height 1, matching the harness's Zebra config.
    fn all_active_regtest() -> ArgosParams {
        ArgosParams::regtest_all_active()
    }

    #[test]
    fn regtest_params_report_regtest_network_type() {
        assert_eq!(all_active_regtest().network_type(), NetworkType::Regtest);
    }

    #[test]
    fn regtest_params_activate_ironwood() {
        let params = all_active_regtest();
        assert_eq!(
            params.activation_height(NetworkUpgrade::Nu6_3),
            Some(BlockHeight::from_u32(1)),
            "Ironwood must be active on the regtest chain"
        );
        assert!(params.is_nu_active(NetworkUpgrade::Nu6_3, BlockHeight::from_u32(200)));
    }

    /// The actual regression: this is what a sweep signs with.
    #[test]
    fn regtest_branch_id_at_harness_heights_is_ironwood() {
        let params = all_active_regtest();
        for height in [1u32, 200, 300, 1_000] {
            assert_eq!(
                BranchId::for_height(&params, BlockHeight::from_u32(height)),
                BranchId::Nu6_3,
                "height {height} must resolve to the Ironwood branch"
            );
        }
    }

    /// Guards the bug this type was introduced to prevent: testnet params on a
    /// short regtest chain resolve to a pre-NU5 branch.
    #[test]
    fn testnet_params_would_pick_the_wrong_branch_on_a_regtest_chain() {
        let testnet = consensus_network(ZeckNetwork::Testnet);
        let branch = BranchId::for_height(&testnet, BlockHeight::from_u32(200));
        assert_ne!(
            branch,
            BranchId::Nu6_3,
            "testnet params must NOT be usable for regtest sweeps"
        );
    }

    #[test]
    fn production_networks_are_unaffected() {
        assert_eq!(
            consensus_network(ZeckNetwork::Mainnet).network_type(),
            NetworkType::Main
        );
        assert_eq!(
            consensus_network(ZeckNetwork::Testnet).network_type(),
            NetworkType::Test
        );
        assert_eq!(
            consensus_network(ZeckNetwork::Mainnet).activation_height(NetworkUpgrade::Nu6_3),
            Some(BlockHeight::from_u32(3_428_143)),
            "mainnet Ironwood activation height must come through unchanged"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use secrecy::{ExposeSecret, SecretString};
    use zip32::fingerprint::SeedFingerprint;

    use super::*;
    use crate::derivation::mnemonic_seed;
    use crate::key_source::ImportedKeySource;
    use crate::models::RuntimeScanConfig;

    fn config(
        seed: &str,
        birthday: u32,
        num_accounts: Option<u32>,
        gap_limit: u32,
        network: ZeckNetwork,
    ) -> RuntimeScanConfig {
        RuntimeScanConfig {
            seed_phrase: SecretString::new(seed.to_owned()),
            birthday,
            num_accounts,
            gap_limit,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            data_dir: PathBuf::from("/tmp/zeck-test-data"),
            network,
            label: String::new(),
        }
    }

    fn runtime_config(seed: &str) -> RuntimeScanConfig {
        config(seed, 3_280_000, None, 20, ZeckNetwork::Mainnet)
    }

    const SEED: &str = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon art";

    const OTHER_SEED: &str = "legal winner thank year wave sausage worth \
                              useful legal winner thank year wave sausage \
                              worth useful legal winner thank year wave \
                              sausage worth title";

    #[test]
    fn identical_args_produce_identical_workspace_path() {
        let a = RecoveryWorkspace::from_runtime(&config(
            SEED,
            3_280_000,
            None,
            20,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        let b = RecoveryWorkspace::from_runtime(&config(
            SEED,
            3_280_000,
            None,
            20,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn different_birthday_uses_different_workspace() {
        let a = RecoveryWorkspace::from_runtime(&config(
            SEED,
            3_280_000,
            None,
            20,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        let b = RecoveryWorkspace::from_runtime(&config(
            SEED,
            2_500_000,
            None,
            20,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn different_gap_limit_uses_different_workspace() {
        let a = RecoveryWorkspace::from_runtime(&config(
            SEED,
            3_280_000,
            None,
            20,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        let b = RecoveryWorkspace::from_runtime(&config(
            SEED,
            3_280_000,
            None,
            40,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn explicit_num_accounts_uses_different_workspace_than_gap_limit() {
        let a = RecoveryWorkspace::from_runtime(&config(
            SEED,
            3_280_000,
            None,
            20,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        let b = RecoveryWorkspace::from_runtime(&config(
            SEED,
            3_280_000,
            Some(20),
            20,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        assert_ne!(
            a.root(),
            b.root(),
            "auto-gap and explicit num-accounts use different scan strategies and \
             must persist to separate workspaces"
        );
    }

    #[test]
    fn different_network_uses_different_workspace() {
        let a = RecoveryWorkspace::from_runtime(&config(
            SEED,
            3_280_000,
            None,
            20,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        let b = RecoveryWorkspace::from_runtime(&config(
            SEED,
            3_280_000,
            None,
            20,
            ZeckNetwork::Testnet,
        ))
        .unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn different_seed_uses_different_workspace() {
        let a = RecoveryWorkspace::from_runtime(&config(
            SEED,
            3_280_000,
            None,
            20,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        let b = RecoveryWorkspace::from_runtime(&config(
            OTHER_SEED,
            3_280_000,
            None,
            20,
            ZeckNetwork::Mainnet,
        ))
        .unwrap();
        assert_ne!(a.root(), b.root());
    }

    #[test]
    fn workspace_root_lives_under_data_dir() {
        let cfg = config(SEED, 3_280_000, None, 20, ZeckNetwork::Mainnet);
        let ws = RecoveryWorkspace::from_runtime(&cfg).unwrap();
        assert!(
            ws.root().starts_with(&cfg.data_dir),
            "workspace root {} must live under data_dir {}",
            ws.root().display(),
            cfg.data_dir.display(),
        );
    }

    #[test]
    fn workspace_path_does_not_leak_seed_fingerprint() {
        let cfg = config(SEED, 3_280_000, None, 20, ZeckNetwork::Mainnet);
        let ws = RecoveryWorkspace::from_runtime(&cfg).unwrap();
        let path_str = ws.root().display().to_string();

        let seed = mnemonic_seed(&cfg.seed_phrase).expect("seed should derive");
        let fingerprint_str = SeedFingerprint::from_seed(seed.expose_secret())
            .expect("seed fingerprint should derive")
            .to_string();

        assert!(
            !path_str.contains(&fingerprint_str),
            "workspace path must not contain the literal seed fingerprint"
        );
        assert!(
            path_str.contains("workspace-"),
            "workspace path should use the hash-prefixed segment"
        );
    }

    #[test]
    fn session_metadata_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let meta = SessionMetadata::new_in_progress(
            "Old Zecwallet".to_owned(),
            ZeckNetwork::Mainnet,
            3_280_000,
            Some(3_400_000),
            1_715_000_000,
        );
        write_session_metadata(dir.path(), &meta).expect("write");
        let read = read_session_metadata(dir.path())
            .expect("read")
            .expect("present");
        assert_eq!(read, meta);
    }

    #[test]
    fn read_session_metadata_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(read_session_metadata(dir.path()).expect("read").is_none());
    }

    #[test]
    fn read_session_metadata_returns_none_for_corrupt_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(SESSION_FILE_NAME), b"not json").expect("write");
        assert!(read_session_metadata(dir.path()).expect("read").is_none());
    }

    #[test]
    fn mark_session_completed_flips_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let meta = SessionMetadata::new_in_progress(
            "x".to_owned(),
            ZeckNetwork::Testnet,
            2_000_000,
            None,
            1,
        );
        write_session_metadata(dir.path(), &meta).expect("write");
        mark_session_completed(dir.path(), 2).expect("mark");
        let read = read_session_metadata(dir.path())
            .expect("read")
            .expect("present");
        assert!(read.completed);
        assert_eq!(read.last_run_at_epoch_seconds, 2);
    }

    #[test]
    fn parse_workspace_keying_auto_gap() {
        let path =
            PathBuf::from("/tmp/data/mainnet/workspace-deadbeef/birthday-3280000/auto-gap-20");
        let keying = parse_workspace_keying(&path).expect("parse");
        assert_eq!(keying.network, ZeckNetwork::Mainnet);
        assert_eq!(keying.birthday, 3_280_000);
        assert_eq!(keying.num_accounts, None);
        assert_eq!(keying.gap_limit, 20);
    }

    #[test]
    fn parse_workspace_keying_explicit_accounts() {
        let path =
            PathBuf::from("/tmp/data/testnet/workspace-cafebabe/birthday-2400000/accounts-15");
        let keying = parse_workspace_keying(&path).expect("parse");
        assert_eq!(keying.network, ZeckNetwork::Testnet);
        assert_eq!(keying.num_accounts, Some(15));
        assert_eq!(keying.gap_limit, 15);
    }

    #[test]
    fn verify_seed_for_workspace_accepts_matching_seed() {
        let cfg = config(SEED, 3_280_000, None, 20, ZeckNetwork::Mainnet);
        let ws = RecoveryWorkspace::from_runtime(&cfg).unwrap();
        verify_seed_for_workspace(ws.root(), &SecretString::new(SEED.to_owned()))
            .expect("matching seed verifies");
    }

    #[test]
    fn verify_seed_for_workspace_rejects_other_seed() {
        let cfg = config(SEED, 3_280_000, None, 20, ZeckNetwork::Mainnet);
        let ws = RecoveryWorkspace::from_runtime(&cfg).unwrap();
        let err = verify_seed_for_workspace(ws.root(), &SecretString::new(OTHER_SEED.to_owned()))
            .expect_err("mismatched seed must fail");
        assert!(matches!(err, ZeckError::InvalidConfig(_)));
    }

    #[test]
    fn list_incomplete_sessions_filters_completed_and_listsboth_legacy_and_marked() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        // Workspace 1: incomplete with sidecar.
        let cfg1 = RuntimeScanConfig {
            seed_phrase: SecretString::new(SEED.to_owned()),
            birthday: 3_280_000,
            num_accounts: None,
            gap_limit: 20,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            data_dir: data_dir.path().to_owned(),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let ws1 = RecoveryWorkspace::from_runtime(&cfg1).unwrap();
        std::fs::create_dir_all(ws1.root()).unwrap();
        // Stand in for wallet.sqlite — we just need the file to exist for
        // the listing to consider this dir; reading the summary will fail
        // gracefully and fall back to None.
        std::fs::write(ws1.root().join("wallet.sqlite"), b"").unwrap();
        write_session_metadata(
            ws1.root(),
            &SessionMetadata::new_in_progress(
                "labeled scan".to_owned(),
                ZeckNetwork::Mainnet,
                3_280_000,
                Some(3_500_000),
                100,
            ),
        )
        .unwrap();

        // Workspace 2: legacy, no sidecar.
        let cfg2 = RuntimeScanConfig {
            seed_phrase: SecretString::new(OTHER_SEED.to_owned()),
            birthday: 3_280_000,
            num_accounts: None,
            gap_limit: 20,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            data_dir: data_dir.path().to_owned(),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let ws2 = RecoveryWorkspace::from_runtime(&cfg2).unwrap();
        std::fs::create_dir_all(ws2.root()).unwrap();
        std::fs::write(ws2.root().join("wallet.sqlite"), b"").unwrap();

        // Workspace 3: completed — must be filtered out.
        let cfg3 = RuntimeScanConfig {
            seed_phrase: SecretString::new(SEED.to_owned()),
            birthday: 2_500_000,
            num_accounts: None,
            gap_limit: 20,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            data_dir: data_dir.path().to_owned(),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let ws3 = RecoveryWorkspace::from_runtime(&cfg3).unwrap();
        std::fs::create_dir_all(ws3.root()).unwrap();
        std::fs::write(ws3.root().join("wallet.sqlite"), b"").unwrap();
        let mut completed = SessionMetadata::new_in_progress(
            "done".to_owned(),
            ZeckNetwork::Mainnet,
            2_500_000,
            Some(3_000_000),
            50,
        );
        completed.completed = true;
        write_session_metadata(ws3.root(), &completed).unwrap();

        let rows = list_incomplete_sessions(data_dir.path()).expect("list");
        assert_eq!(rows.len(), 2, "expected ws1 and ws2, got {rows:?}");
        let labels: Vec<&str> = rows.iter().map(|r| r.label.as_str()).collect();
        assert!(labels.contains(&"labeled scan"));
        assert!(labels.contains(&"(unlabeled scan)"));
        // Ordering: labeled scan has last_run_at=100, legacy has None — labeled first.
        assert_eq!(rows[0].label, "labeled scan");
    }

    #[test]
    fn list_incomplete_sessions_empty_for_missing_data_dir() {
        let rows = list_incomplete_sessions(Path::new("/tmp/zeck-nonexistent-zzz")).expect("list");
        assert!(rows.is_empty());
    }

    #[test]
    fn workspace_path_does_not_change_across_releases() {
        // Snapshot the keying so an accidental change to the path layout
        // shows up as a test failure rather than a silently-orphaned
        // workspace on every user's disk.
        const EXPECTED_WORKSPACE_ID_FOR_TEST_SEED: &str = "b5e2cf2baecd3446f65e96a40159123d";
        let cfg = config(SEED, 3_280_000, None, 20, ZeckNetwork::Mainnet);
        let ws = RecoveryWorkspace::from_runtime(&cfg).unwrap();
        let suffix = ws
            .root()
            .strip_prefix(&cfg.data_dir)
            .unwrap()
            .to_string_lossy()
            .to_string();
        // network / workspace-<hash> / birthday-N / auto-gap-M
        let parts: Vec<&str> = suffix.split('/').collect();
        assert_eq!(parts.len(), 4, "unexpected workspace path layout: {suffix}");
        assert_eq!(parts[0], "mainnet");
        assert_eq!(
            parts[1],
            format!("workspace-{EXPECTED_WORKSPACE_ID_FOR_TEST_SEED}"),
            "workspace id changed for the fixed test seed — if intentional, \
             update EXPECTED_WORKSPACE_ID_FOR_TEST_SEED, but be aware this \
             means every existing user's workspace dir is now orphaned"
        );
        assert_eq!(parts[2], "birthday-3280000");
        assert_eq!(parts[3], "auto-gap-20");
    }

    #[test]
    fn workspace_id_is_deterministic_and_distinct_across_inputs() {
        let cfg = config(SEED, 3_280_000, None, 20, ZeckNetwork::Mainnet);
        let seed = mnemonic_seed(&cfg.seed_phrase).unwrap();
        let fp = SeedFingerprint::from_seed(seed.expose_secret()).unwrap();
        let fp = fp.to_string();
        let a = derive_workspace_id(ZeckNetwork::Mainnet, &fp, 3_280_000, "auto-gap-20");
        let b = derive_workspace_id(ZeckNetwork::Mainnet, &fp, 3_280_000, "auto-gap-20");
        assert_eq!(a, b);
        let c = derive_workspace_id(ZeckNetwork::Mainnet, &fp, 3_280_001, "auto-gap-20");
        assert_ne!(a, c);
        let d = derive_workspace_id(ZeckNetwork::Testnet, &fp, 3_280_000, "auto-gap-20");
        assert_ne!(a, d);
    }

    #[test]
    fn a_seed_workspace_path_is_unchanged_by_the_refactor() {
        // Regression guard: existing users must resume their scans. If
        // this fails, every in-progress scan on disk is orphaned.
        //
        // `old` is built via `from_runtime`, which is untouched call-site
        // code — it still does its own seed -> SeedFingerprint -> path
        // derivation inline (see above). `new` goes through the added
        // `from_key_source` + `KeySource::workspace_path_component` seam.
        // These are two independent code paths computing the same path,
        // not one path compared against itself.
        let cfg = runtime_config(SEED);
        let old = RecoveryWorkspace::from_runtime(&cfg).unwrap();
        let source = SeedKeySource::new(cfg.seed_phrase.clone());
        let new = RecoveryWorkspace::from_key_source(&source, &cfg).unwrap();
        assert_eq!(old.wallet_db_path(), new.wallet_db_path());
    }

    #[test]
    fn an_imported_workspace_differs_from_a_seed_workspace() {
        let cfg = runtime_config(SEED);
        let seed_ws =
            RecoveryWorkspace::from_key_source(&SeedKeySource::new(cfg.seed_phrase.clone()), &cfg)
                .unwrap();
        let imported = ImportedKeySource::new(argos_wallet_import::ImportedKeys::default());
        let imported_ws = RecoveryWorkspace::from_key_source(&imported, &cfg).unwrap();
        assert_ne!(seed_ws.wallet_db_path(), imported_ws.wallet_db_path());
    }

    #[test]
    fn the_workspace_path_still_does_not_leak_the_fingerprint() {
        let cfg = runtime_config(SEED);
        let source = SeedKeySource::new(cfg.seed_phrase.clone());
        let ws = RecoveryWorkspace::from_key_source(&source, &cfg).unwrap();
        let fp = source.fingerprint().unwrap().to_hex();
        let path = ws.wallet_db_path().display().to_string();
        assert!(!path.contains(&fp), "workspace path leaks the fingerprint");
    }

    // ─── Workspace permissions (R-W21..R-W23) ─────────────────────────────────
    //
    // T-L1 in the threat model. The pure-keying tests above prove the
    // *path* is correct; these tests prove the *permissions* on what's at
    // that path. Unix-only — the Windows/macOS-with-FileVault story is
    // documented in the threat model rather than tested.

    #[cfg(unix)]
    #[test]
    fn create_private_dir_all_sets_mode_0o700_on_leaf() {
        // R-W21: the leaf workspace directory must be created `0o700` so
        // other local users (and other-process malware running as a
        // different uid) cannot read FVKs/IVKs/note caches.
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let leaf = temp.path().join("workspace-leaf");
        super::create_private_dir_all(&leaf).expect("create_private_dir_all should succeed");
        let mode = std::fs::metadata(&leaf)
            .expect("metadata")
            .permissions()
            .mode();
        // Only inspect the permission bits — file type bits live in the upper
        // half of `mode` and are not what we're asserting.
        assert_eq!(
            mode & 0o777,
            0o700,
            "leaf workspace dir mode is {:o}",
            mode & 0o777
        );
    }

    #[cfg(unix)]
    #[test]
    fn set_private_file_permissions_sets_mode_0o600_on_file() {
        // R-W22: a freshly-created file inside the workspace gets `0o600`
        // applied via `set_private_file_permissions`. Argos invokes this on
        // wallet.sqlite / blocks.sqlite immediately after creation.
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let file = temp.path().join("private.bin");
        std::fs::write(&file, b"sensitive").expect("write file");
        // Force a permissive starting mode so the test actually proves the
        // tightening step ran, not just that defaults happened to be 0o600.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
            .expect("seed perms");
        super::set_private_file_permissions(&file).expect("set perms");
        let mode = std::fs::metadata(&file)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "file mode is {:o}", mode & 0o777);
    }

    #[cfg(unix)]
    #[test]
    fn write_session_metadata_creates_file_with_mode_0o600() {
        // Audit Suggestion 3: session.json must be created with 0o600 at
        // creation time, not rely solely on the 0o700 parent directory.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let meta = SessionMetadata::new_in_progress(
            "perm check".to_owned(),
            ZeckNetwork::Mainnet,
            3_280_000,
            None,
            1,
        );
        write_session_metadata(dir.path(), &meta).expect("write");
        let mode = std::fs::metadata(dir.path().join(SESSION_FILE_NAME))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "session.json mode is {:o}",
            mode & 0o777
        );
    }

    #[test]
    fn workspace_path_handles_unicode_data_dir() {
        // R-W23: data-dir paths containing non-ASCII characters (Cyrillic,
        // CJK, etc.) must produce a workspace path that round-trips through
        // String/PathBuf without mangling. Defends against a regression that
        // would lose data on macOS users with localised account names.
        let cfg = RuntimeScanConfig {
            seed_phrase: SecretString::new(SEED.to_owned()),
            birthday: 3_280_000,
            num_accounts: None,
            gap_limit: 20,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            data_dir: PathBuf::from("/tmp/zeck-tëst-ñam-日本/data"),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let ws = RecoveryWorkspace::from_runtime(&cfg).expect("workspace from unicode data_dir");
        // Round-trip the path through String and back: this is what the
        // sidecar JSON serialisation does in practice. A mangling regression
        // would surface as a path inequality after the round-trip.
        let as_string = ws.root().to_string_lossy().into_owned();
        let back = PathBuf::from(&as_string);
        assert_eq!(
            ws.root(),
            back,
            "unicode path mangled through string round-trip"
        );
        // And the path actually contains the unicode segment, not a
        // percent-encoded or stripped version.
        assert!(as_string.contains("tëst"));
        assert!(as_string.contains("日本"));
    }

    // ─── wallet DB connection tuning ──────────────────────────────────────
    //
    // `zcash_client_sqlite` sets no journal_mode/synchronous/busy_timeout
    // pragmas itself. These tests pin that every wallet DB opened through
    // `open_tuned_wallet_connection` gets WAL + NORMAL + busy-timeout.

    #[test]
    fn tuned_wallet_connection_sets_wal_normal_and_busy_timeout() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let path = tempdir.path().join("wallet.sqlite");

        let conn = super::open_tuned_wallet_connection(&path).expect("open tuned connection");

        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("query journal_mode");
        assert_eq!(
            journal_mode.to_ascii_lowercase(),
            "wal",
            "wallet DB must run in WAL mode so the progress poller never blocks the scan writer"
        );

        let synchronous: i64 = conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .expect("query synchronous");
        assert_eq!(synchronous, 1, "synchronous must be NORMAL (1) in WAL mode");

        let busy_timeout_ms: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .expect("query busy_timeout");
        assert_eq!(
            busy_timeout_ms,
            i64::try_from(super::WALLET_DB_BUSY_TIMEOUT_SECS * 1_000).expect("timeout fits"),
            "busy_timeout must wait on lock contention instead of failing immediately"
        );
    }

    #[test]
    fn wal_mode_persists_for_untuned_readers() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let path = tempdir.path().join("wallet.sqlite");

        let conn = super::open_tuned_wallet_connection(&path).expect("open tuned connection");
        drop(conn);

        let plain = rusqlite::Connection::open(&path).expect("plain reopen");
        let journal_mode: String = plain
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("query journal_mode");
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
    }

    #[test]
    fn open_wallet_db_succeeds_on_fresh_and_existing_files() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let path = tempdir.path().join("wallet.sqlite");
        let network = super::consensus_network(crate::models::ZeckNetwork::Mainnet);

        let db = super::open_wallet_db(&path, network).expect("open fresh wallet db");
        drop(db);
        super::open_wallet_db(&path, network).expect("reopen existing wallet db");
    }
}
