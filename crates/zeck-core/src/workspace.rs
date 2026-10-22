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
    models::{RuntimeScanConfig, TransparentScanConfig, ZeckNetwork},
    private_fs::{self, PrivateOpenMode},
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
    /// this wallet — used to verify private access without touching the
    /// generic data_dir or network directories above it.
    private_root: PathBuf,
    wallet_db_path: PathBuf,
}

/// Retained create-time authority for files exported into one recovery
/// workspace. Holding this value pins the private workspace root while a UI
/// resolves the destination and publishes the file through an exact parent
/// handle.
pub struct PrivateWorkspaceFileAuthority {
    workspace_root: PathBuf,
    private_root: PathBuf,
    lineage: private_fs::PrivateRootLineageLease,
}

impl PrivateWorkspaceFileAuthority {
    pub fn acquire(workspace_root: impl AsRef<Path>) -> ZeckResult<Self> {
        let workspace_root = workspace_root.as_ref().to_path_buf();
        let database = workspace_root.join("wallet.sqlite");
        let private_root = private_root_for_wallet_database(&database).map_err(|err| {
            ZeckError::Storage(format!(
                "deriving private authority for recovery workspace {}: {err}",
                workspace_root.display()
            ))
        })?;
        let lineage =
            private_fs::verify_private_workspace_lineage(private_root).map_err(|err| {
                ZeckError::Storage(format!(
                    "authenticating recovery workspace {}: {err}",
                    workspace_root.display()
                ))
            })?;
        verify_private_dirs(private_root, &workspace_root)?;
        Ok(Self {
            workspace_root,
            private_root: private_root.to_path_buf(),
            lineage,
        })
    }

    pub fn write_private_file(&self, path: &Path, bytes: &[u8]) -> ZeckResult<()> {
        let parent = path.parent().ok_or_else(|| {
            ZeckError::Storage(format!("private export {} has no parent", path.display()))
        })?;
        if !parent.starts_with(&self.workspace_root) || path.file_name().is_none() {
            return Err(ZeckError::Storage(format!(
                "private export {} is outside recovery workspace {}",
                path.display(),
                self.workspace_root.display()
            )));
        }

        self.lineage.verify_current().map_err(|err| {
            ZeckError::Storage(format!(
                "revalidating recovery workspace before export: {err}"
            ))
        })?;
        private_fs::create_private_dir_all(parent).map_err(|err| {
            ZeckError::Storage(format!(
                "creating private report directory {}: {err}",
                parent.display()
            ))
        })?;
        verify_private_dirs(&self.private_root, parent)?;
        let retained_parent = private_fs::open_private_directory_lease(parent).map_err(|err| {
            ZeckError::Storage(format!(
                "retaining private report directory {}: {err}",
                parent.display()
            ))
        })?;
        self.lineage.verify_current().map_err(|err| {
            ZeckError::Storage(format!(
                "revalidating recovery workspace before report write: {err}"
            ))
        })?;
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                return Err(ZeckError::Storage(format!(
                    "private export {} is not a regular file",
                    path.display()
                )))
            }
            Ok(_) => {
                private_fs::verify_private_child_file(&retained_parent, path).map_err(|err| {
                    ZeckError::Storage(format!(
                        "verifying existing private export {}: {err}",
                        path.display()
                    ))
                })?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(ZeckError::Storage(format!(
                    "inspecting private export {}: {error}",
                    path.display()
                )))
            }
        }
        private_fs::write_private_file_atomic_in_parent(&retained_parent, path, bytes).map_err(
            |err| ZeckError::Storage(format!("writing private export {}: {err}", path.display())),
        )?;
        self.lineage.verify_current().map_err(|err| {
            ZeckError::Storage(format!(
                "revalidating recovery workspace after report write: {err}"
            ))
        })
    }
}

impl RecoveryWorkspace {
    pub fn from_runtime(config: &RuntimeScanConfig) -> ZeckResult<Self> {
        Self::from_key_source(config.key_source.as_ref(), config)
    }

    /// Build a workspace from any key source.
    ///
    /// `from_runtime` remains as a thin wrapper so existing seed callers
    /// and their on-disk workspaces are untouched. For a seed source this
    /// must produce byte-identical paths to the old implementation, or
    /// every in-progress scan on disk is orphaned.
    pub fn from_key_source(source: &dyn KeySource, config: &RuntimeScanConfig) -> ZeckResult<Self> {
        let path_component = source.workspace_path_component()?;

        if let Some(range) = config.transparent_scan {
            range.validate()?;
        }
        let scope = scan_scope_segment(
            config.num_accounts,
            config.gap_limit,
            config.transparent_scan,
        );

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

    pub(crate) fn initialize(&self, network: ZeckNetwork, seed: &[u8; 64]) -> ZeckResult<()> {
        self.ensure_private_lineage()?;
        // Verify every component from the wallet-private root down so resumes
        // fail closed instead of repairing a previously insecure directory.
        verify_private_dirs(&self.private_root, &self.root)?;

        let mut wallet_db = open_wallet_db(&self.wallet_db_path, consensus_network(network))?;
        init_wallet_db(&mut wallet_db, Some(SecretVec::new(seed.to_vec()))).map_err(|err| {
            ZeckError::Wallet(format!(
                "initializing wallet database {}: {err}",
                self.wallet_db_path.display()
            ))
        })?;
        set_private_file_permissions(&self.wallet_db_path)?;
        // WAL mode adds `-wal`/`-shm` sidecar files; verify them too.
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
    pub(crate) fn initialize_from_source(
        &self,
        network: ZeckNetwork,
        source: &dyn KeySource,
    ) -> ZeckResult<()> {
        self.ensure_private_lineage()?;
        verify_private_dirs(&self.private_root, &self.root)?;

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

    pub(crate) fn private_root(&self) -> &Path {
        &self.private_root
    }

    pub fn wallet_db_path(&self) -> &Path {
        &self.wallet_db_path
    }

    pub(crate) fn authorize_recreation(&self) -> ZeckResult<()> {
        private_fs::authorize_private_workspace_recreation(
            &self.private_root,
            &self.root,
            &self.wallet_db_path,
        )
        .map_err(|err| {
            ZeckError::Storage(format!(
                "authorizing a new recovery generation at {}: {err}",
                self.root.display()
            ))
        })
    }

    pub fn broadcast_log_path(&self) -> PathBuf {
        self.root.join(crate::broadcast::BROADCAST_LOG_FILE_NAME)
    }

    /// Establish the private workspace before the broadcast lock sidecar is opened.
    pub(crate) fn ensure_broadcast_log_directory(&self) -> ZeckResult<()> {
        self.ensure_private_lineage()?;
        verify_private_dirs(&self.private_root, &self.root)
    }

    fn ensure_private_lineage(&self) -> ZeckResult<()> {
        private_fs::ensure_private_workspace_lineage(
            &self.private_root,
            &self.root,
            &self.wallet_db_path,
        )
        .map(|_| ())
        .map_err(|err| {
            ZeckError::Storage(format!(
                "establishing private workspace lineage at {}: {err}",
                self.private_root.display()
            ))
        })
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

#[cfg(test)]
fn create_private_dir_all(path: &Path) -> ZeckResult<()> {
    private_fs::create_private_dir_all(path)
        .map_err(|err| ZeckError::Storage(format!("creating {}: {err}", path.display())))
}

#[allow(unused_variables)]
fn verify_private_dirs(private_root: &Path, leaf: &Path) -> ZeckResult<()> {
    let mut current = leaf.to_path_buf();
    loop {
        private_fs::harden_private_directory(&current).map_err(|err| {
            ZeckError::Storage(format!(
                "verifying private permissions on {}: {err}",
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

    Ok(())
}

fn set_private_file_permissions(path: &Path) -> ZeckResult<()> {
    let file = private_fs::open_private_file(path, PrivateOpenMode::Append).map_err(|err| {
        ZeckError::Storage(format!(
            "verifying private permissions on {}: {err}",
            path.display()
        ))
    })?;
    private_fs::harden_private_file(&file).map_err(|err| {
        ZeckError::Storage(format!(
            "verifying private permissions on {}: {err}",
            path.display()
        ))
    })
}

/// Append one complete JSONL event and make it durable before reporting success.
/// The caller provides JSON bytes without a trailing newline.
pub(crate) fn append_private_file(path: &Path, bytes: &[u8]) -> ZeckResult<()> {
    use std::io::Write;

    let created = !path.exists();
    let mut file = private_fs::open_private_file(path, PrivateOpenMode::Append).map_err(|err| {
        ZeckError::Storage(format!("opening {} for append: {err}", path.display()))
    })?;
    // One buffer, one write: the event and its terminator are never split
    // across separate writes.
    let mut line = Vec::with_capacity(bytes.len() + 1);
    line.extend_from_slice(bytes);
    line.push(b'\n');
    file.write_all(&line)
        .and_then(|_| file.flush())
        .and_then(|_| file.sync_all())
        .map_err(|err| {
            ZeckError::Storage(format!("appending and syncing {}: {err}", path.display()))
        })?;
    if created {
        let parent = path.parent().ok_or_else(|| {
            ZeckError::Storage(format!(
                "broadcast log {} has no parent directory",
                path.display()
            ))
        })?;
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(|err| {
                ZeckError::Storage(format!(
                    "syncing broadcast log parent {}: {err}",
                    parent.display()
                ))
            })?;
    }
    Ok(())
}

/// Seconds a wallet-database connection waits on a locked database before
/// returning `SQLITE_BUSY`. The scan writer and the once-per-second progress
/// poller share the file, so lock collisions are routine rather than exceptional.
const WALLET_DB_BUSY_TIMEOUT_SECS: u64 = 5;

fn private_root_for_wallet_database(path: &Path) -> std::io::Result<&Path> {
    path.parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "wallet database path does not have the expected private-root/birthday/scope layout",
            )
        })
}

fn open_authorized_wallet_connection(
    path: &Path,
    flags: rusqlite::OpenFlags,
    prepare_wal_sidecars: bool,
    initialize: impl FnOnce(&rusqlite::Connection, bool) -> Result<(), rusqlite::Error>,
) -> Result<rusqlite::Connection, rusqlite::Error> {
    fn sqlite_io(error: std::io::Error) -> rusqlite::Error {
        rusqlite::Error::ToSqlConversionFailure(Box::new(error))
    }

    let parent_path = path.parent().ok_or_else(|| {
        sqlite_io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wallet database has no parent directory",
        ))
    })?;
    let private_root = private_root_for_wallet_database(path).map_err(sqlite_io)?;
    let _open_guard = private_fs::lock_private_sqlite_open(path).map_err(sqlite_io)?;
    let root = private_fs::verify_private_workspace_lineage(private_root).map_err(sqlite_io)?;
    let parent = private_fs::open_private_sqlite_parent(parent_path).map_err(sqlite_io)?;
    let mut sidecars = Vec::with_capacity(3);
    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_owned();
        sidecar.push(suffix);
        let sidecar = PathBuf::from(sidecar);
        let existed = match fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                private_fs::verify_private_child_file(&parent, &sidecar).map_err(sqlite_io)?;
                true
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(sqlite_io(error)),
        };
        sidecars.push((sidecar, existed));
    }
    let wal_authority = if prepare_wal_sidecars {
        Some(private_fs::prepare_private_sqlite_wal_sidecars(&parent, path).map_err(sqlite_io)?)
    } else {
        None
    };
    private_fs::ensure_private_sqlite_file(&root, &parent, parent_path, path).map_err(sqlite_io)?;
    let database_was_empty = fs::metadata(path).map_err(sqlite_io)?.len() == 0;
    let connection = rusqlite::Connection::open_with_flags(path, flags)?;
    let initialize_result = initialize(&connection, database_was_empty);
    let sidecar_result = if let Some(authority) = wal_authority {
        authority
            .verify_current()
            .map_err(sqlite_io)
            .and_then(|()| {
                let (journal, existed) = &sidecars[0];
                match fs::symlink_metadata(journal) {
                    Ok(_) if *existed => Ok(()),
                    Ok(_) => private_fs::secure_new_private_child_file(&parent, journal)
                        .map_err(sqlite_io),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(sqlite_io(error)),
                }
            })
    } else {
        let mut result = Ok(());
        for (sidecar, existed) in sidecars {
            let checked = match fs::symlink_metadata(&sidecar) {
                Ok(_) if existed => Ok(()),
                Ok(_) => private_fs::secure_new_private_child_file(&parent, &sidecar),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = checked {
                result = Err(sqlite_io(error));
                break;
            }
        }
        result
    };
    sidecar_result?;
    initialize_result?;
    Ok(connection)
}

pub(crate) fn open_wallet_connection_read_only(
    path: &Path,
) -> Result<rusqlite::Connection, rusqlite::Error> {
    open_authorized_wallet_connection(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        false,
        |_, _| Ok(()),
    )
}

/// Open the wallet database for launch-time session listing without allowing
/// SQLite to create a journal, WAL, or shared-memory sidecar. `immutable=1`
/// keeps even a read-only WAL connection from creating `-shm`; `query_only`
/// adds a second, connection-local refusal for accidental write statements.
///
/// This is intentionally separate from [`open_wallet_connection_read_only`].
/// Runtime readers must observe committed WAL frames while a scan writer is
/// live. Launch-time listing runs before recovery authority is acquired and
/// may accept a slightly stale displayed height rather than touch recovery
/// storage.
fn open_wallet_connection_for_listing(
    path: &Path,
) -> Result<rusqlite::Connection, rusqlite::Error> {
    fn sqlite_io(error: std::io::Error) -> rusqlite::Error {
        rusqlite::Error::ToSqlConversionFailure(Box::new(error))
    }

    let parent_path = path.parent().ok_or_else(|| {
        sqlite_io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wallet database has no parent directory",
        ))
    })?;
    let private_root = private_root_for_wallet_database(path).map_err(sqlite_io)?;
    let _open_guard = private_fs::lock_private_sqlite_open(path).map_err(sqlite_io)?;
    let root = private_fs::verify_private_workspace_lineage(private_root).map_err(sqlite_io)?;
    let parent = private_fs::open_private_sqlite_parent(parent_path).map_err(sqlite_io)?;
    private_fs::ensure_private_sqlite_file(&root, &parent, parent_path, path).map_err(sqlite_io)?;

    let canonical_path = fs::canonicalize(path).map_err(sqlite_io)?;
    let path = canonical_path
        .to_str()
        .ok_or_else(|| rusqlite::Error::InvalidPath(canonical_path.clone()))?;
    let mut uri = String::with_capacity(path.len() + 32);
    uri.push_str("file:");
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/' | b':' | b'\\')
        {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[usize::from(byte >> 4)]));
            uri.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    uri.push_str("?mode=ro&immutable=1");

    let connection = rusqlite::Connection::open_with_flags(
        uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.pragma_update(None, "query_only", "ON")?;
    connection.busy_timeout(std::time::Duration::from_secs(WALLET_DB_BUSY_TIMEOUT_SECS))?;
    Ok(connection)
}

/// Opens a raw SQLite connection with the tuning Argos requires:
/// WAL journal mode, `synchronous=NORMAL`, and a busy timeout.
///
/// `zcash_client_sqlite` deliberately leaves connection tuning to the embedder;
/// its `WalletDb::for_path` opens with SQLite defaults (rollback journal,
/// `synchronous=FULL`, no busy timeout). All production opens of `wallet.sqlite`
/// should come through [`open_wallet_db`] instead.
fn open_tuned_wallet_connection(path: &Path) -> Result<rusqlite::Connection, rusqlite::Error> {
    open_authorized_wallet_connection(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        true,
        |conn, database_was_empty| {
            // `WalletDb::from_connection` requires the array module to be loaded.
            rusqlite::vtab::array::load_module(conn)?;
            conn.busy_timeout(std::time::Duration::from_secs(WALLET_DB_BUSY_TIMEOUT_SECS))?;
            let journal_mode: String =
                conn.pragma_query_value(None, "journal_mode", |row| row.get::<_, String>(0))?;
            if !journal_mode.eq_ignore_ascii_case("wal") {
                if !database_was_empty {
                    return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
                        std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "a non-empty private wallet database is not already in WAL mode",
                        ),
                    )));
                }
                // SQLite uses a rollback-journal transaction to enter WAL
                // mode. This is allowed only while the newly staged database
                // is still empty, before it can contain wallet material. WAL
                // and SHM are already private and retained before the change.
                let resulting_mode =
                    conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| {
                        row.get::<_, String>(0)
                    })?;
                if !resulting_mode.eq_ignore_ascii_case("wal") {
                    return Err(rusqlite::Error::ToSqlConversionFailure(Box::new(
                        std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            format!(
                                "SQLite refused WAL mode for the private wallet database and remained in {resulting_mode} mode"
                            ),
                        ),
                    )));
                }
            }
            conn.pragma_update(None, "synchronous", "NORMAL")?;
            // A zero-byte database can enter WAL mode without opening its WAL
            // object. Exhausting a schema read forces the pager to open and
            // retain the exact pre-created WAL/SHM files before Argos releases
            // its no-delete authority handles.
            let mut statement = conn.prepare("PRAGMA table_list")?;
            let mut rows = statement.query([])?;
            while rows.next()?.is_some() {}
            Ok(())
        },
    )
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
    /// Public derivation coordinates for an address-match handoff. The seed
    /// and optional BIP-39 passphrase are deliberately never persisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_coordinates: Option<crate::address_match_recovery::MatchCoordinates>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparent_scan: Option<TransparentScanConfig>,
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
            match_coordinates: None,
            transparent_scan: None,
        }
    }

    pub fn with_transparent_scan(mut self, range: Option<TransparentScanConfig>) -> Self {
        self.transparent_scan = range;
        self
    }

    pub fn with_match_coordinates(
        mut self,
        coordinates: Option<crate::address_match_recovery::MatchCoordinates>,
    ) -> Self {
        self.match_coordinates = coordinates;
        self
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_coordinates: Option<crate::address_match_recovery::MatchCoordinates>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transparent_scan: Option<TransparentScanConfig>,
    /// This workspace cannot be resumed from its persisted state and must be
    /// recreated by rescanning from the original recovery material.
    #[serde(default)]
    pub requires_rescan: bool,
    /// The workspace predates (or fails) the create-time private-storage
    /// lineage boundary. No file inside it was parsed to construct this row.
    #[serde(default)]
    pub legacy_untrusted: bool,
}

fn session_path(workspace_root: &Path) -> PathBuf {
    workspace_root.join(SESSION_FILE_NAME)
}

fn verify_existing_workspace_authority(
    workspace_root: &Path,
) -> std::io::Result<(private_fs::PrivateRootLineageLease, fs::File)> {
    let private_root = workspace_root
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "workspace root does not have the expected private-root/birthday/scope layout",
            )
        })?;
    let root = private_fs::verify_private_workspace_lineage(private_root)?;
    let parent = private_fs::open_private_sqlite_parent(workspace_root)?;
    let database = workspace_root.join("wallet.sqlite");
    private_fs::ensure_private_sqlite_file(&root, &parent, workspace_root, &database)?;
    Ok((root, parent))
}

/// Atomic write: write to `<path>.tmp` then rename. Best-effort guarantee
/// that a crash mid-write does not leave a half-written sidecar.
pub(crate) fn write_session_metadata(
    workspace_root: &Path,
    meta: &SessionMetadata,
) -> ZeckResult<()> {
    let (_root, parent) = verify_existing_workspace_authority(workspace_root).map_err(|err| {
        ZeckError::Storage(format!(
            "verifying workspace authority {}: {err}",
            workspace_root.display()
        ))
    })?;
    let final_path = session_path(workspace_root);
    let bytes =
        serde_json::to_vec_pretty(meta).map_err(|err| ZeckError::Serialization(err.to_string()))?;
    private_fs::write_private_file_atomic_in_parent(&parent, &final_path, &bytes)
        .map_err(|err| ZeckError::Storage(format!("writing {}: {err}", final_path.display())))
}

/// Read the sidecar at `workspace_root/session.json`. Returns `Ok(None)` if
/// missing or unparseable; only filesystem errors other than "not found"
/// surface as `Err`. Treating corrupt sidecars as missing keeps the launch
/// list robust against a bad write — the workspace is still usable, just
/// shows up as legacy.
pub fn read_session_metadata(workspace_root: &Path) -> ZeckResult<Option<SessionMetadata>> {
    let path = session_path(workspace_root);
    let (_root, parent) = verify_existing_workspace_authority(workspace_root).map_err(|err| {
        ZeckError::Storage(format!(
            "verifying workspace authority {}: {err}",
            workspace_root.display()
        ))
    })?;
    let bytes = match private_fs::read_private_child_file(&parent, &path) {
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
pub(crate) fn mark_session_completed(
    workspace_root: &Path,
    now_epoch_seconds: i64,
) -> ZeckResult<()> {
    let Some(mut meta) = read_session_metadata(workspace_root)? else {
        return Ok(());
    };
    meta.completed = true;
    meta.last_run_at_epoch_seconds = now_epoch_seconds;
    write_session_metadata(workspace_root, &meta)
}

/// Update `last_run_at` on an existing sidecar. Best-effort — any error is
/// returned to the caller, who is expected to swallow it on the hot path.
pub(crate) fn touch_session_last_run(
    workspace_root: &Path,
    now_epoch_seconds: i64,
) -> ZeckResult<()> {
    let Some(mut meta) = read_session_metadata(workspace_root)? else {
        return Ok(());
    };
    meta.last_run_at_epoch_seconds = now_epoch_seconds;
    write_session_metadata(workspace_root, &meta)
}

/// Walk `data_dir` and return resumable incomplete workspaces plus preserved
/// legacy workspaces that require a fresh scan. A candidate that fails the
/// create-time lineage boundary is described only from validated path
/// components; its session metadata and wallet database are never parsed.
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
            if !is_workspace_id_segment(&workspace_entry.file_name()) {
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

fn is_workspace_id_segment(name: &std::ffi::OsStr) -> bool {
    let Some(id) = name
        .to_str()
        .and_then(|name| name.strip_prefix("workspace-"))
    else {
        return false;
    };
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Build one row for the launch-time list. Returns `None` when the candidate
/// workspace is complete, or when the wallet database is missing/unreadable
/// (i.e. there is nothing to resume).
fn try_build_incomplete_row(
    workspace_path: &Path,
    network: ZeckNetwork,
    birthday: u32,
) -> Option<IncompleteSession> {
    let keying = parse_workspace_keying(workspace_path).ok()?;
    if keying.network != network || keying.birthday != birthday {
        return None;
    }

    if verify_existing_workspace_authority(workspace_path).is_err() {
        return Some(IncompleteSession {
            workspace_path: workspace_path.to_owned(),
            label: "Legacy workspace — rescan required".to_owned(),
            network: keying.network,
            birthday: keying.birthday,
            synced_to_height: None,
            target_height: None,
            last_run_at_epoch_seconds: None,
            match_coordinates: None,
            transparent_scan: keying.transparent_scan,
            requires_rescan: true,
            legacy_untrusted: true,
        });
    }

    let wallet_db_path = workspace_path.join("wallet.sqlite");

    let meta = read_session_metadata(workspace_path).ok().flatten();
    if meta.as_ref().map(|m| m.completed).unwrap_or(false) {
        return None;
    }

    let synced_to_height = read_synced_height(&wallet_db_path, network);

    let (label, target_height, last_run_at, match_coordinates) = match meta {
        Some(m) => (
            m.label,
            m.target_height,
            Some(m.last_run_at_epoch_seconds),
            m.match_coordinates,
        ),
        None => ("(unlabeled scan)".to_owned(), None, None, None),
    };

    Some(IncompleteSession {
        workspace_path: workspace_path.to_owned(),
        label,
        network,
        birthday,
        synced_to_height,
        target_height,
        last_run_at_epoch_seconds: last_run_at,
        match_coordinates,
        // Scope in the hashed workspace path is authoritative.
        transparent_scan: keying.transparent_scan,
        requires_rescan: false,
        legacy_untrusted: false,
    })
}

fn read_synced_height(wallet_db_path: &Path, network: ZeckNetwork) -> Option<u32> {
    let connection = open_wallet_connection_for_listing(wallet_db_path).ok()?;
    rusqlite::vtab::array::load_module(&connection).ok()?;
    let wallet_db =
        WalletDb::from_connection(connection, consensus_network(network), SystemClock, OsRng);
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
    scan_scope_segment(
        keying.num_accounts,
        keying.gap_limit,
        keying.transparent_scan,
    )
}

fn scan_scope_segment(
    accounts: Option<u32>,
    gap: u32,
    range: Option<TransparentScanConfig>,
) -> String {
    let mut scope = match accounts {
        Some(count) => format!("accounts-{count}"),
        None => format!("auto-gap-{gap}"),
    };
    if let Some(range) = range {
        let branch = if range.include_change {
            "both"
        } else {
            "receive"
        };
        scope.push_str(&format!(
            "-transparent-{}-{}-{branch}",
            range.index_start, range.index_count
        ));
    }
    scope
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
    pub transparent_scan: Option<TransparentScanConfig>,
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

    let (scope, transparent_scan) = if let Some((base, range)) = scope.split_once("-transparent-") {
        let mut parts = range.split('-');
        let malformed = || ZeckError::InvalidConfig("malformed transparent scan scope".to_owned());
        let index_start = parts
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(malformed)?;
        let index_count = parts
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(malformed)?;
        let include_change = match parts.next() {
            Some("receive") => false,
            Some("both") => true,
            _ => return Err(malformed()),
        };
        if parts.next().is_some() {
            return Err(malformed());
        }
        let range = TransparentScanConfig {
            index_start,
            index_count,
            include_change,
        };
        range.validate()?;
        (base, Some(range))
    } else {
        (scope.as_str(), None)
    };

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
        transparent_scan,
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
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::SystemTime;

    use secrecy::{ExposeSecret, SecretString};
    use zip32::fingerprint::SeedFingerprint;

    use super::*;
    use crate::derivation::mnemonic_seed;
    use crate::key_source::ImportedKeySource;
    use crate::models::RuntimeScanConfig;

    #[test]
    fn append_private_file_writes_whole_terminated_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        super::append_private_file(&path, br#"{"a":1}"#).unwrap();
        super::append_private_file(&path, br#"{"b":2}"#).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"a\":1}\n{\"b\":2}\n");
    }

    fn private_test_directory(tempdir: &tempfile::TempDir) -> PathBuf {
        let private_root = tempdir.path().join("publication/private-root");
        let workspace = private_root.join("birthday-1/auto-gap-20");
        let database = workspace.join("wallet.sqlite");
        crate::private_fs::ensure_private_workspace_lineage(&private_root, &workspace, &database)
            .expect("lineaged private test workspace");
        workspace
    }

    #[test]
    fn private_workspace_file_authority_publishes_inside_verified_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = private_test_directory(&dir);
        let authority = PrivateWorkspaceFileAuthority::acquire(&workspace).unwrap();
        let report = workspace.join("reports/recovery.json");

        authority
            .write_private_file(&report, b"private recovery report")
            .unwrap();

        assert_eq!(fs::read(&report).unwrap(), b"private recovery report");
        authority.write_private_file(&report, b"updated").unwrap();
        assert_eq!(fs::read(&report).unwrap(), b"updated");
    }

    #[cfg(unix)]
    #[test]
    fn private_workspace_file_authority_refuses_reused_permissive_file_unchanged() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let workspace = private_test_directory(&dir);
        let authority = PrivateWorkspaceFileAuthority::acquire(&workspace).unwrap();
        let report = workspace.join("recovery.json");
        fs::write(&report, b"legacy bytes").unwrap();
        fs::set_permissions(&report, fs::Permissions::from_mode(0o644)).unwrap();

        let error = authority
            .write_private_file(&report, b"new bytes")
            .expect_err("permissive reuse must remain untrusted")
            .to_string();

        assert!(error.contains("private export"), "{error}");
        assert_eq!(fs::read(&report).unwrap(), b"legacy bytes");
        assert_eq!(
            fs::metadata(&report).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_workspace_file_authority_refuses_workspace_path_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = private_test_directory(&dir);
        let authority = PrivateWorkspaceFileAuthority::acquire(&workspace).unwrap();
        let private_root = workspace.parent().unwrap().parent().unwrap();
        let displaced = dir.path().join("displaced-private-root");
        fs::rename(private_root, &displaced).unwrap();
        crate::private_fs::create_private_dir_all(&workspace).unwrap();
        let report = workspace.join("recovery.json");

        authority
            .write_private_file(&report, b"must not publish")
            .expect_err("the authenticated workspace pathname was replaced");

        assert!(!report.exists());
    }

    fn file_tree_snapshot(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, SystemTime)> {
        fn visit(
            root: &Path,
            current: &Path,
            files: &mut BTreeMap<PathBuf, (Vec<u8>, SystemTime)>,
        ) {
            let mut entries = fs::read_dir(current)
                .expect("read snapshot directory")
                .collect::<Result<Vec<_>, _>>()
                .expect("collect snapshot directory");
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).expect("snapshot metadata");
                if metadata.is_dir() {
                    visit(root, &path, files);
                } else if metadata.is_file() {
                    files.insert(
                        path.strip_prefix(root)
                            .expect("snapshot relative path")
                            .to_owned(),
                        (
                            fs::read(&path).expect("snapshot file bytes"),
                            metadata.modified().expect("snapshot modification time"),
                        ),
                    );
                }
            }
        }

        let mut files = BTreeMap::new();
        visit(root, root, &mut files);
        files
    }

    fn config(
        seed: &str,
        birthday: u32,
        num_accounts: Option<u32>,
        gap_limit: u32,
        network: ZeckNetwork,
    ) -> RuntimeScanConfig {
        RuntimeScanConfig {
            key_source: Arc::new(SeedKeySource::new(SecretString::new(seed.to_owned()))),
            birthday,
            num_accounts,
            gap_limit,
            transparent_scan: None,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            confirmation_sources: Vec::new(),
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

        let seed = mnemonic_seed(&SecretString::new(SEED.to_owned())).expect("seed should derive");
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
        let root = private_test_directory(&dir);
        let meta = SessionMetadata::new_in_progress(
            "Old Zecwallet".to_owned(),
            ZeckNetwork::Mainnet,
            3_280_000,
            Some(3_400_000),
            1_715_000_000,
        );
        write_session_metadata(&root, &meta).expect("write");
        let read = read_session_metadata(&root)
            .expect("read")
            .expect("present");
        assert_eq!(read, meta);
    }

    #[test]
    fn read_session_metadata_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = private_test_directory(&dir);
        assert!(read_session_metadata(&root).expect("read").is_none());
    }

    #[test]
    fn read_session_metadata_returns_none_for_corrupt_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = private_test_directory(&dir);
        crate::private_fs::write_private_file(&root.join(SESSION_FILE_NAME), b"not json")
            .expect("write private corrupt metadata");
        assert!(read_session_metadata(&root).expect("read").is_none());
    }

    #[test]
    fn mark_session_completed_flips_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = private_test_directory(&dir);
        let meta = SessionMetadata::new_in_progress(
            "x".to_owned(),
            ZeckNetwork::Testnet,
            2_000_000,
            None,
            1,
        );
        write_session_metadata(&root, &meta).expect("write");
        mark_session_completed(&root, 2).expect("mark");
        let read = read_session_metadata(&root)
            .expect("read")
            .expect("present");
        assert!(read.completed);
        assert_eq!(read.last_run_at_epoch_seconds, 2);
    }

    #[test]
    fn transparent_range_is_part_of_workspace_identity_and_resume_keying() {
        let legacy = runtime_config(SEED);
        let legacy_workspace = RecoveryWorkspace::from_runtime(&legacy).unwrap();
        assert_eq!(
            parse_workspace_keying(legacy_workspace.root())
                .unwrap()
                .transparent_scan,
            None
        );
        let ranges = [
            TransparentScanConfig::default(),
            TransparentScanConfig {
                index_start: 900,
                index_count: 100,
                include_change: false,
            },
            TransparentScanConfig {
                index_start: 900,
                index_count: 100,
                include_change: true,
            },
        ];
        let mut paths = std::collections::HashSet::new();
        for range in ranges {
            let mut config = legacy.clone();
            config.transparent_scan = Some(range);
            let workspace = RecoveryWorkspace::from_runtime(&config).unwrap();
            assert_ne!(workspace.root(), legacy_workspace.root());
            assert!(paths.insert(workspace.root().to_owned()));
            let keying = parse_workspace_keying(workspace.root()).unwrap();
            assert_eq!(keying.transparent_scan, Some(range));
            assert_eq!(keying.num_accounts, config.num_accounts);
            verify_key_source_for_workspace(workspace.root(), config.key_source.as_ref()).unwrap();
            let mut resumed = config.clone();
            resumed.transparent_scan = keying.transparent_scan;
            assert_eq!(
                RecoveryWorkspace::from_runtime(&resumed).unwrap().root(),
                workspace.root()
            );
        }
    }

    #[test]
    fn invalid_transparent_workspace_ranges_are_rejected() {
        for scope in [
            "accounts-1-transparent-0-0-receive",
            "accounts-1-transparent-2147483647-2-receive",
            "accounts-1-transparent-0-10001-receive",
            "accounts-1-transparent-0-1000-other",
            "accounts-1-transparent-0-1000-both-extra",
        ] {
            let path = PathBuf::from("/tmp/data/mainnet/workspace-id/birthday-3280000").join(scope);
            assert!(parse_workspace_keying(&path).is_err(), "{scope}");
        }
    }

    #[test]
    fn transparent_range_metadata_is_public_and_legacy_metadata_still_loads() {
        let range = TransparentScanConfig {
            index_start: 997,
            index_count: 12,
            include_change: true,
        };
        let meta =
            SessionMetadata::new_in_progress("fixture".into(), ZeckNetwork::Mainnet, 1, None, 0)
                .with_transparent_scan(Some(range));
        let mut json = serde_json::to_value(&meta).unwrap();
        let loaded: SessionMetadata = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(loaded.transparent_scan, Some(range));
        json.as_object_mut().unwrap().remove("transparent_scan");
        let old: SessionMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(old.transparent_scan, None);
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
    fn list_incomplete_sessions_filters_completed_and_lists_both_legacy_and_marked() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        // Workspace 1: incomplete with sidecar.
        let cfg1 = RuntimeScanConfig {
            key_source: Arc::new(SeedKeySource::new(SecretString::new(SEED.to_owned()))),
            birthday: 3_280_000,
            num_accounts: None,
            gap_limit: 20,
            transparent_scan: None,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: data_dir.path().to_owned(),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let ws1 = RecoveryWorkspace::from_runtime(&cfg1).unwrap();
        ws1.ensure_private_lineage().unwrap();
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
            key_source: Arc::new(SeedKeySource::new(SecretString::new(OTHER_SEED.to_owned()))),
            birthday: 3_280_000,
            num_accounts: None,
            gap_limit: 20,
            transparent_scan: None,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: data_dir.path().to_owned(),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let ws2 = RecoveryWorkspace::from_runtime(&cfg2).unwrap();
        super::create_private_dir_all(ws2.root()).unwrap();
        std::fs::write(ws2.root().join("wallet.sqlite"), b"").unwrap();

        // Workspace 3: completed — must be filtered out.
        let cfg3 = RuntimeScanConfig {
            key_source: Arc::new(SeedKeySource::new(SecretString::new(SEED.to_owned()))),
            birthday: 2_500_000,
            num_accounts: None,
            gap_limit: 20,
            transparent_scan: None,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: data_dir.path().to_owned(),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let ws3 = RecoveryWorkspace::from_runtime(&cfg3).unwrap();
        ws3.ensure_private_lineage().unwrap();
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
        assert!(labels.contains(&"Legacy workspace — rescan required"));
        let legacy = rows.iter().find(|row| row.legacy_untrusted).unwrap();
        assert!(legacy.requires_rescan);
        assert_eq!(legacy.synced_to_height, None);
        assert_eq!(legacy.target_height, None);
        // Ordering: labeled scan has last_run_at=100, legacy has None — labeled first.
        assert_eq!(rows[0].label, "labeled scan");
    }

    #[test]
    fn listing_a_trusted_workspace_does_not_mutate_its_files() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let cfg = RuntimeScanConfig {
            key_source: Arc::new(SeedKeySource::new(SecretString::new(SEED.to_owned()))),
            birthday: 3_280_000,
            num_accounts: None,
            gap_limit: 20,
            transparent_scan: None,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            confirmation_sources: Vec::new(),
            data_dir: data_dir.path().to_owned(),
            network: ZeckNetwork::Mainnet,
            label: String::new(),
        };
        let workspace = RecoveryWorkspace::from_runtime(&cfg).unwrap();
        workspace.ensure_private_lineage().unwrap();
        let connection =
            rusqlite::Connection::open(workspace.wallet_db_path()).expect("open staged database");
        connection
            .execute_batch("CREATE TABLE listing_sentinel(value BLOB); INSERT INTO listing_sentinel VALUES (x'010203');")
            .expect("write valid SQLite fixture");
        drop(connection);
        write_session_metadata(
            workspace.root(),
            &SessionMetadata::new_in_progress(
                "trusted scan".to_owned(),
                ZeckNetwork::Mainnet,
                3_280_000,
                Some(3_500_000),
                100,
            ),
        )
        .unwrap();

        let before = file_tree_snapshot(workspace.private_root());
        let rows = list_incomplete_sessions(data_dir.path()).expect("list");
        let after = file_tree_snapshot(workspace.private_root());

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "trusted scan");
        assert!(!rows[0].legacy_untrusted);
        assert_eq!(
            after, before,
            "listing must not create or modify recovery files"
        );
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = workspace.wallet_db_path().as_os_str().to_owned();
            sidecar.push(suffix);
            assert!(!PathBuf::from(sidecar).exists(), "listing created {suffix}");
        }
    }

    #[test]
    fn listing_does_not_recreate_a_missing_trusted_database() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = runtime_config(SEED);
        cfg.data_dir = data_dir.path().to_owned();
        let workspace = RecoveryWorkspace::from_runtime(&cfg).unwrap();
        workspace.ensure_private_lineage().unwrap();
        fs::remove_file(workspace.wallet_db_path()).expect("remove staged database");
        let before = file_tree_snapshot(workspace.private_root());

        let rows = list_incomplete_sessions(data_dir.path()).expect("list");
        let after = file_tree_snapshot(workspace.private_root());

        assert_eq!(rows.len(), 1);
        assert!(rows[0].legacy_untrusted);
        assert!(!workspace.wallet_db_path().exists());
        assert_eq!(
            after, before,
            "listing must leave lineage markers unchanged"
        );
    }

    #[test]
    fn listing_reads_an_initialized_trusted_workspace_without_mutation() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let mut cfg = runtime_config(SEED);
        cfg.data_dir = data_dir.path().to_owned();
        let workspace = RecoveryWorkspace::from_runtime(&cfg).unwrap();
        let seed = mnemonic_seed(&SecretString::new(SEED.to_owned())).expect("derive seed");
        workspace
            .initialize(ZeckNetwork::Mainnet, seed.expose_secret())
            .expect("initialize trusted wallet");
        write_session_metadata(
            workspace.root(),
            &SessionMetadata::new_in_progress(
                "initialized trusted scan".to_owned(),
                ZeckNetwork::Mainnet,
                cfg.birthday,
                Some(cfg.birthday + 100),
                123,
            ),
        )
        .unwrap();
        let before = file_tree_snapshot(workspace.private_root());

        let rows = list_incomplete_sessions(data_dir.path()).expect("list initialized workspace");
        let after = file_tree_snapshot(workspace.private_root());

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].label, "initialized trusted scan");
        assert!(!rows[0].requires_rescan);
        assert!(!rows[0].legacy_untrusted);
        assert_eq!(after, before);
    }

    #[test]
    fn list_incomplete_sessions_empty_for_missing_data_dir() {
        let rows = list_incomplete_sessions(Path::new("/tmp/zeck-nonexistent-zzz")).expect("list");
        assert!(rows.is_empty());
    }

    #[test]
    fn untrusted_legacy_workspace_is_listed_for_rescan_without_disk_claims() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let workspace = data_dir
            .path()
            .join("mainnet")
            .join("workspace-deadbeefdeadbeefdeadbeefdeadbeef")
            .join("birthday-3280000")
            .join("accounts-1-transparent-7-3-both");
        std::fs::create_dir_all(&workspace).expect("legacy workspace");
        std::fs::write(
            workspace.join(SESSION_FILE_NAME),
            br#"{
                "schema_version": 1,
                "label": "must not be trusted",
                "network": "mainnet",
                "birthday": 1,
                "target_height": 9999999,
                "last_run_at_epoch_seconds": 42,
                "completed": false
            }"#,
        )
        .expect("legacy session metadata");
        std::fs::write(
            workspace.join("wallet.sqlite"),
            b"must not be parsed as a wallet database",
        )
        .expect("legacy wallet database");

        let before = file_tree_snapshot(data_dir.path());
        let rows = list_incomplete_sessions(data_dir.path()).expect("list");
        let after = file_tree_snapshot(data_dir.path());
        assert_eq!(
            rows.len(),
            1,
            "the preserved legacy workspace needs guidance"
        );
        assert_eq!(
            after, before,
            "legacy listing must not touch untrusted bytes"
        );
        let row = serde_json::to_value(&rows[0]).expect("serialize row");
        assert_eq!(row["requires_rescan"], true);
        assert_eq!(row["legacy_untrusted"], true);
        assert_eq!(row["label"], "Legacy workspace — rescan required");
        assert_eq!(row["network"], "mainnet");
        assert_eq!(row["birthday"], 3_280_000);
        assert_eq!(row["synced_to_height"], serde_json::Value::Null);
        assert_eq!(row["target_height"], serde_json::Value::Null);
        assert_eq!(row["last_run_at_epoch_seconds"], serde_json::Value::Null);
        assert_eq!(row["match_coordinates"], serde_json::Value::Null);
        assert_eq!(row["transparent_scan"]["index_start"], 7);
        assert_eq!(row["transparent_scan"]["index_count"], 3);
        assert_eq!(row["transparent_scan"]["include_change"], true);
    }

    #[test]
    fn malformed_legacy_workspace_id_is_not_listed() {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let workspace = data_dir
            .path()
            .join("mainnet")
            .join("workspace-not-a-wallet-id")
            .join("birthday-3280000")
            .join("auto-gap-20");
        std::fs::create_dir_all(&workspace).expect("legacy workspace");
        std::fs::write(workspace.join("wallet.sqlite"), b"untrusted").unwrap();

        assert!(list_incomplete_sessions(data_dir.path())
            .expect("list")
            .is_empty());
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
        let seed = mnemonic_seed(&SecretString::new(SEED.to_owned())).unwrap();
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

    /// Verbatim copy of the pre-refactor `derive_workspace_id`, which hashed
    /// `fingerprint.to_string()` directly rather than a generalized
    /// `path_component: &str`. Kept here so
    /// `a_seed_workspace_path_is_unchanged_by_the_refactor` compares two
    /// independent derivations rather than the production code against
    /// itself. Do NOT refactor this to call the production helper.
    fn original_workspace_id(
        network: ZeckNetwork,
        fingerprint: &SeedFingerprint,
        birthday: u32,
        scope: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"zeck-workspace-v1\0");
        hasher.update(network.label().as_bytes());
        hasher.update(b"\0");
        hasher.update(fingerprint.to_string().as_bytes());
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

    #[test]
    fn a_seed_workspace_path_is_unchanged_by_the_refactor() {
        // Regression guard: existing users must resume their scans. If
        // this fails, every in-progress scan on disk is orphaned.
        //
        // `expected` is built from `original_workspace_id`, a verbatim
        // copy of the pre-refactor derivation, independent of any
        // production code touched by this change. `actual` goes through
        // the new `from_key_source` + `KeySource::workspace_path_component`
        // seam. This is a genuine differential comparison, not the new
        // code compared against itself.
        let cfg = runtime_config(SEED);
        let seed = mnemonic_seed(&SecretString::new(SEED.to_owned())).unwrap();
        let fingerprint = SeedFingerprint::from_seed(seed.expose_secret()).unwrap();
        let scope = "auto-gap-20";
        let expected_id = original_workspace_id(cfg.network, &fingerprint, cfg.birthday, scope);
        let expected_path = cfg
            .data_dir
            .join(cfg.network.label())
            .join(format!("workspace-{expected_id}"))
            .join(format!("birthday-{}", cfg.birthday))
            .join(scope)
            .join("wallet.sqlite");

        let source = SeedKeySource::new(SecretString::new(SEED.to_owned()));
        let actual = RecoveryWorkspace::from_key_source(&source, &cfg).unwrap();
        assert_eq!(actual.wallet_db_path(), expected_path);
    }

    #[test]
    fn an_imported_workspace_differs_from_a_seed_workspace() {
        let cfg = runtime_config(SEED);
        let seed_ws = RecoveryWorkspace::from_key_source(
            &SeedKeySource::new(SecretString::new(SEED.to_owned())),
            &cfg,
        )
        .unwrap();
        let imported = ImportedKeySource::new(argos_wallet_import::ImportedKeys::default());
        let imported_ws = RecoveryWorkspace::from_key_source(&imported, &cfg).unwrap();
        assert_ne!(seed_ws.wallet_db_path(), imported_ws.wallet_db_path());
    }

    #[test]
    fn the_workspace_path_still_does_not_leak_the_fingerprint() {
        let cfg = runtime_config(SEED);
        let source = SeedKeySource::new(SecretString::new(SEED.to_owned()));
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
    fn set_private_file_permissions_rejects_insecure_reuse_without_repair() {
        // R-W22: reused files must already be `0o600`; chmod cannot revoke a
        // stale descriptor held by another process.
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().expect("tempdir");
        let file = temp.path().join("private.bin");
        std::fs::write(&file, b"sensitive").expect("write file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
            .expect("seed perms");
        super::set_private_file_permissions(&file).expect_err("permissive reuse must fail closed");
        let mode = std::fs::metadata(&file)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o644, "file mode is {:o}", mode & 0o777);
        assert_eq!(std::fs::read(&file).unwrap(), b"sensitive");
    }

    #[cfg(unix)]
    #[test]
    fn write_session_metadata_creates_file_with_mode_0o600() {
        // Audit Suggestion 3: session.json must be created with 0o600 at
        // creation time, not rely solely on the 0o700 parent directory.
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let root = private_test_directory(&dir);
        let meta = SessionMetadata::new_in_progress(
            "perm check".to_owned(),
            ZeckNetwork::Mainnet,
            3_280_000,
            None,
            1,
        );
        write_session_metadata(&root, &meta).expect("write");
        let mode = std::fs::metadata(root.join(SESSION_FILE_NAME))
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
            key_source: Arc::new(SeedKeySource::new(SecretString::new(SEED.to_owned()))),
            birthday: 3_280_000,
            num_accounts: None,
            gap_limit: 20,
            transparent_scan: None,
            lightwalletd_url: "https://example.invalid:443".to_owned(),
            confirmation_sources: Vec::new(),
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

    fn private_database_path(tempdir: &tempfile::TempDir) -> PathBuf {
        let private_root = tempdir.path().join("publication/private-root");
        let leaf = private_root.join("birthday-1/auto-gap-20");
        let database = leaf.join("wallet.sqlite");
        crate::private_fs::ensure_private_workspace_lineage(&private_root, &leaf, &database)
            .expect("staged private test workspace");
        database
    }

    #[test]
    fn tuned_wallet_connection_sets_wal_normal_and_busy_timeout() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let path = private_database_path(&tempdir);

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
        let path = private_database_path(&tempdir);

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
        let path = private_database_path(&tempdir);
        let network = super::consensus_network(crate::models::ZeckNetwork::Mainnet);

        let db = super::open_wallet_db(&path, network).expect("open fresh wallet db");
        drop(db);
        super::open_wallet_db(&path, network).expect("reopen existing wallet db");
    }

    #[test]
    fn nonempty_rollback_database_is_refused_without_a_wal_transition() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let path = private_database_path(&tempdir);
        let raw = rusqlite::Connection::open(&path).expect("open rollback-mode fixture");
        raw.execute_batch("CREATE TABLE rollback_fixture(value INTEGER);")
            .expect("write rollback-mode fixture");
        let mode: String = raw
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("read fixture journal mode");
        assert_eq!(mode.to_ascii_lowercase(), "delete");
        drop(raw);

        let error = super::open_tuned_wallet_connection(&path)
            .expect_err("nonempty rollback-mode databases must fail closed");
        assert!(
            error
                .to_string()
                .contains("non-empty private wallet database is not already in WAL mode"),
            "unexpected refusal: {error}"
        );

        let raw = rusqlite::Connection::open(&path).expect("reopen unchanged fixture");
        let mode: String = raw
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("re-read fixture journal mode");
        assert_eq!(mode.to_ascii_lowercase(), "delete");
    }

    #[test]
    fn listing_wallet_connection_is_immutable_and_query_only() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let path = private_database_path(&tempdir);
        let writer = rusqlite::Connection::open(&path).expect("open fixture writer");
        writer
            .execute_batch(
                "CREATE TABLE listing_guard(value INTEGER); INSERT INTO listing_guard VALUES (7);",
            )
            .expect("initialize fixture");
        drop(writer);
        let before = fs::read(&path).expect("database bytes before listing open");

        let connection = super::open_wallet_connection_for_listing(&path)
            .expect("open immutable listing connection");
        let query_only: bool = connection
            .pragma_query_value(None, "query_only", |row| row.get(0))
            .expect("read query_only");
        assert!(query_only);
        assert_eq!(
            connection
                .query_row("SELECT value FROM listing_guard", [], |row| row
                    .get::<_, i64>(0))
                .expect("read fixture"),
            7
        );
        assert!(connection
            .execute("INSERT INTO listing_guard VALUES (8)", [])
            .is_err());
        drop(connection);

        assert_eq!(fs::read(&path).unwrap(), before);
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_owned();
            sidecar.push(suffix);
            assert!(
                !PathBuf::from(sidecar).exists(),
                "listing open created {suffix}"
            );
        }
    }

    #[test]
    fn tuned_wallet_connections_allow_a_concurrent_reader() {
        let tempdir = tempfile::tempdir().expect("temp dir");
        let path = private_database_path(&tempdir);
        let writer = super::open_tuned_wallet_connection(&path).expect("open writer connection");
        #[cfg(windows)]
        {
            let parent_path = path.parent().expect("database parent");
            let parent = crate::private_fs::open_private_sqlite_parent(parent_path)
                .expect("open retained private parent");
            for suffix in ["-wal", "-shm"] {
                let mut sidecar = path.as_os_str().to_owned();
                sidecar.push(suffix);
                let sidecar = PathBuf::from(sidecar);
                let replacement = sidecar.with_extension(format!("{suffix}.replacement"));
                crate::private_fs::rename_child_file(&parent, &sidecar, &replacement)
                    .expect_err("SQLite must keep its live WAL sidecar name pinned");
                assert!(sidecar.exists());
                assert!(!replacement.exists());
            }
        }
        writer
            .execute_batch(
                "CREATE TABLE held_open(value INTEGER); INSERT INTO held_open VALUES (7);",
            )
            .expect("initialize through writer");

        let reader = super::open_tuned_wallet_connection(&path)
            .expect("open reader while writer connection remains live");
        let value: i64 = reader
            .query_row("SELECT value FROM held_open", [], |row| row.get(0))
            .expect("read while writer remains live");
        assert_eq!(value, 7);
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_permissive_sqlite_sidecar_fails_before_connection_mutation() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let tempdir = tempfile::tempdir().expect("temp dir");
        let path = private_database_path(&tempdir);
        let database_before = fs::metadata(&path).expect("database metadata before preflight");
        let sidecar = path.with_file_name("wallet.sqlite-wal");
        fs::write(&sidecar, b"must survive").unwrap();
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o644)).unwrap();

        super::open_tuned_wallet_connection(&path)
            .expect_err("an insecure existing sidecar must fail before SQLite opens");

        assert_eq!(fs::read(&sidecar).unwrap(), b"must survive");
        assert_eq!(fs::metadata(&sidecar).unwrap().mode() & 0o7777, 0o644);
        let database_after = fs::metadata(&path).expect("database remains after refusal");
        assert_eq!(
            (
                database_after.dev(),
                database_after.ino(),
                database_after.len()
            ),
            (
                database_before.dev(),
                database_before.ino(),
                database_before.len()
            ),
            "sidecar refusal must leave the staged database object unchanged"
        );
    }
}
