//! Download a pinned Sprout pack.
//!
//! The server is not trusted. The manifest must hash to the value this
//! release pins before any chunk is requested, and every chunk must match the
//! length and SHA-256 the manifest gives it before it is kept. A mirror that
//! serves anything else is skipped for the next one. So a mirror can make the
//! download fail or fall back to the full p2p walk, but it cannot change what
//! a scan reads.
//!
//! Files land in a cache folder named by the manifest hash. A chunk is written
//! to `chunk-NNNN.bin.partial` and renamed only once it checks out, so an
//! interrupted download resumes from the first chunk it does not have.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::error::ZeckResult;
use crate::p2p::wire::P2pNetwork;
use crate::sprout_pack::{
    chunk_file_name, from_hex32, pack_error, to_hex, ChunkEntry, PackManifest, SproutPack,
    MANIFEST_FILE, MAX_MANIFEST_BYTES, PINNED_PACKS,
};

/// A pack to download: what it must hash to, and where to look for it.
#[derive(Debug, Clone)]
pub struct PackSource {
    pub network: P2pNetwork,
    pub manifest_sha256: [u8; 32],
    pub end_height: u32,
    /// Base URLs, each ending in `/`, tried in order. A file's URL is the base
    /// followed by its name.
    pub mirrors: Vec<String>,
}

impl PackSource {
    /// The pack this release pins for `network`, if any.
    pub fn pinned(network: P2pNetwork) -> Option<Self> {
        let pin = PINNED_PACKS.iter().find(|pin| pin.network == network)?;
        Some(Self {
            network,
            manifest_sha256: from_hex32(pin.manifest_sha256)?,
            end_height: pin.end_height,
            mirrors: pin.mirrors.iter().map(|m| m.to_string()).collect(),
        })
    }

    /// The folder this pack is cached in under `data_dir`.
    pub fn cache_dir(&self, data_dir: &Path) -> PathBuf {
        data_dir.join("sprout-packs").join(format!(
            "{}-{}-{}",
            network_slug(self.network),
            self.end_height,
            to_hex(&self.manifest_sha256)
        ))
    }
}

fn network_slug(network: P2pNetwork) -> &'static str {
    match network {
        P2pNetwork::Mainnet => "mainnet",
        P2pNetwork::Testnet => "testnet",
        P2pNetwork::Regtest => "regtest",
    }
}

/// The pack worth downloading for a scan on `network` that has already
/// reached `scanned_to`, if any: the pinned pack, unless the scan is already
/// at or past its end and would read nothing from it.
pub fn pack_to_download(network: P2pNetwork, scanned_to: Option<u32>) -> Option<PackSource> {
    let source = PackSource::pinned(network)?;
    match scanned_to {
        Some(height) if height >= source.end_height => None,
        _ => Some(source),
    }
}

/// How the download talks to mirrors.
#[derive(Debug, Clone)]
pub struct FetchOptions {
    /// Refuse plain `http` mirrors and redirects. Always on outside tests.
    pub require_https: bool,
    /// Use proxies named in the environment (`HTTPS_PROXY` and so on).
    pub use_env_proxy: bool,
    pub connect_timeout: Duration,
    /// How long a mirror may send nothing before the request is dropped.
    pub read_timeout: Duration,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            require_https: true,
            use_env_proxy: true,
            connect_timeout: Duration::from_secs(20),
            read_timeout: Duration::from_secs(60),
        }
    }
}

/// Where a download has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchProgress {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub chunks_done: usize,
    pub chunks_total: usize,
}

/// The HTTP client the download uses.
///
/// Installs the ring crypto provider first: reqwest is built without one of
/// its own and panics if none is installed.
pub fn http_client(options: &FetchOptions) -> ZeckResult<reqwest::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut builder = reqwest::Client::builder()
        .connect_timeout(options.connect_timeout)
        .read_timeout(options.read_timeout)
        .https_only(options.require_https)
        .redirect(reqwest::redirect::Policy::limited(5));
    if !options.use_env_proxy {
        builder = builder.no_proxy();
    }
    builder
        .build()
        .map_err(|err| pack_error(format!("could not set up HTTPS ({})", err.without_url())))
}

/// Download the pack `source` names into `dir`, reusing whatever is already
/// there and checks out, and open it.
///
/// `cancel` is checked between reads; setting it stops the download with an
/// error, keeping the chunks already finished.
pub async fn fetch_pack(
    source: &PackSource,
    dir: &Path,
    options: &FetchOptions,
    cancel: &AtomicBool,
    mut progress: impl FnMut(FetchProgress),
) -> ZeckResult<SproutPack> {
    let mirrors = usable_mirrors(source, options)?;
    let client = http_client(options)?;
    fs::create_dir_all(dir).map_err(|err| file_error(dir, err))?;

    let manifest = match cached_manifest(dir, source)? {
        Some(manifest) => manifest,
        None => download_manifest(&client, &mirrors, source, dir, cancel).await?,
    };
    if manifest.network != source.network || manifest.end_height != source.end_height {
        return Err(pack_error(format!(
            "the pinned manifest describes {:?} to height {}, not {:?} to height {}",
            manifest.network, manifest.end_height, source.network, source.end_height
        )));
    }

    let mut state = FetchProgress {
        bytes_done: 0,
        bytes_total: manifest.total_bytes(),
        chunks_done: 0,
        chunks_total: manifest.chunks.len(),
    };
    let mut missing = Vec::new();
    for (index, entry) in manifest.chunks.iter().enumerate() {
        if cached_chunk_ok(dir.join(chunk_file_name(index)), entry.clone()).await? {
            state.bytes_done += entry.byte_len;
            state.chunks_done += 1;
        } else {
            missing.push(index);
        }
    }
    progress(state);

    // Start each chunk at the mirror that served the last one.
    let mut preferred = 0;
    for index in missing {
        check_cancel(cancel)?;
        let entry = &manifest.chunks[index];
        let name = chunk_file_name(index);
        let base = state.bytes_done;
        let mut failures = Vec::new();
        let mut done = false;
        for offset in 0..mirrors.len() {
            let which = (preferred + offset) % mirrors.len();
            let result = download_chunk(&client, &mirrors[which], dir, &name, entry, cancel, |n| {
                state.bytes_done = base + n;
                progress(state);
            })
            .await;
            match result {
                Ok(()) => {
                    preferred = which;
                    done = true;
                    break;
                }
                Err(Failure::Cancelled) => return Err(cancelled()),
                Err(Failure::Mirror(why)) => failures.push(mirror_failure(&mirrors[which], &why)),
            }
        }
        if !done {
            return Err(pack_error(format!(
                "could not download {name} from any mirror: {}",
                failures.join("; ")
            )));
        }
        state.bytes_done = base + entry.byte_len;
        state.chunks_done += 1;
        progress(state);
    }
    SproutPack::open(dir, source.network)
}

/// Why one mirror could not supply one file.
enum Failure {
    Cancelled,
    Mirror(String),
}

fn cancelled() -> crate::error::ZeckError {
    pack_error("the download was cancelled; the chunks already finished are kept")
}

fn check_cancel(cancel: &AtomicBool) -> ZeckResult<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(cancelled())
    } else {
        Ok(())
    }
}

fn file_error(path: &Path, err: std::io::Error) -> crate::error::ZeckError {
    pack_error(format!("{}: {err}", path.display()))
}

/// Names a mirror by host only, so an error never carries a signed redirect
/// query string or a full path.
fn mirror_failure(mirror: &reqwest::Url, why: &str) -> String {
    format!("{}: {why}", mirror.host_str().unwrap_or("mirror"))
}

fn usable_mirrors(source: &PackSource, options: &FetchOptions) -> ZeckResult<Vec<reqwest::Url>> {
    let mut usable = Vec::new();
    let mut refused = Vec::new();
    for mirror in &source.mirrors {
        match reqwest::Url::parse(mirror) {
            Ok(url) if !mirror.ends_with('/') => refused.push(format!("{url} (not a folder URL)")),
            Ok(url) if options.require_https && url.scheme() != "https" => {
                refused.push(format!("{url} (not https)"))
            }
            Ok(url) => usable.push(url),
            Err(err) => refused.push(format!("{mirror} ({err})")),
        }
    }
    if usable.is_empty() {
        return Err(pack_error(format!(
            "no usable https mirror for the pack{}",
            if refused.is_empty() {
                String::new()
            } else {
                format!(": {}", refused.join(", "))
            }
        )));
    }
    Ok(usable)
}

/// The manifest already in `dir`, if it is the pinned one.
fn cached_manifest(dir: &Path, source: &PackSource) -> ZeckResult<Option<PackManifest>> {
    let path = dir.join(MANIFEST_FILE);
    let Ok(bytes) = fs::read(&path) else {
        return Ok(None);
    };
    if bytes.len() as u64 > MAX_MANIFEST_BYTES
        || <[u8; 32]>::from(Sha256::digest(&bytes)) != source.manifest_sha256
    {
        return Ok(None);
    }
    PackManifest::from_bytes(&bytes).map(Some)
}

async fn download_manifest(
    client: &reqwest::Client,
    mirrors: &[reqwest::Url],
    source: &PackSource,
    dir: &Path,
    cancel: &AtomicBool,
) -> ZeckResult<PackManifest> {
    let mut failures = Vec::new();
    for mirror in mirrors {
        let mut bytes = Vec::new();
        let got = get(
            client,
            mirror,
            MANIFEST_FILE,
            MAX_MANIFEST_BYTES,
            cancel,
            |piece| {
                bytes.extend_from_slice(piece);
            },
        )
        .await;
        match got {
            Err(Failure::Cancelled) => return Err(cancelled()),
            Err(Failure::Mirror(why)) => failures.push(mirror_failure(mirror, &why)),
            Ok(()) => {
                let hash: [u8; 32] = Sha256::digest(&bytes).into();
                if hash != source.manifest_sha256 {
                    failures.push(mirror_failure(
                        mirror,
                        &format!(
                            "its manifest hashes to {}, not the pinned {}",
                            to_hex(&hash),
                            to_hex(&source.manifest_sha256)
                        ),
                    ));
                    continue;
                }
                let manifest = PackManifest::from_bytes(&bytes)?;
                let path = dir.join(MANIFEST_FILE);
                let partial = dir.join(format!("{MANIFEST_FILE}.partial"));
                fs::write(&partial, &bytes).map_err(|err| file_error(&partial, err))?;
                fs::rename(&partial, &path).map_err(|err| file_error(&path, err))?;
                return Ok(manifest);
            }
        }
    }
    Err(pack_error(format!(
        "could not download the pinned {MANIFEST_FILE} from any mirror: {}",
        failures.join("; ")
    )))
}

/// Whether the chunk at `path` is complete and matches `entry`. A file that
/// does not is removed.
async fn cached_chunk_ok(path: PathBuf, entry: ChunkEntry) -> ZeckResult<bool> {
    tokio::task::spawn_blocking(move || {
        let Ok(meta) = fs::metadata(&path) else {
            return Ok(false);
        };
        let matches = meta.len() == entry.byte_len && {
            let mut file = fs::File::open(&path).map_err(|err| file_error(&path, err))?;
            let mut hasher = Sha256::new();
            std::io::copy(&mut file, &mut hasher).map_err(|err| file_error(&path, err))?;
            <[u8; 32]>::from(hasher.finalize()) == entry.sha256
        };
        if !matches {
            fs::remove_file(&path).map_err(|err| file_error(&path, err))?;
        }
        Ok(matches)
    })
    .await
    .map_err(|err| pack_error(format!("checking a cached chunk failed ({err})")))?
}

/// Download one chunk from one mirror into `dir`, keeping it only if it
/// matches `entry`.
async fn download_chunk(
    client: &reqwest::Client,
    mirror: &reqwest::Url,
    dir: &Path,
    name: &str,
    entry: &ChunkEntry,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<(), Failure> {
    let path = dir.join(name);
    let partial = dir.join(format!("{name}.partial"));
    let io = |err: std::io::Error| Failure::Mirror(format!("{}: {err}", partial.display()));
    let mut file = fs::File::create(&partial).map_err(io)?;
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut write_err = None;
    let got = get(client, mirror, name, entry.byte_len, cancel, |piece| {
        if write_err.is_some() {
            return;
        }
        if let Err(err) = file.write_all(piece) {
            write_err = Some(err);
            return;
        }
        hasher.update(piece);
        written += piece.len() as u64;
        progress(written);
    })
    .await;
    let checked = got.and_then(|()| {
        if let Some(err) = write_err {
            return Err(io(err));
        }
        if written != entry.byte_len {
            return Err(Failure::Mirror(format!(
                "{name} is {written} bytes, the manifest says {}",
                entry.byte_len
            )));
        }
        if <[u8; 32]>::from(hasher.finalize()) != entry.sha256 {
            return Err(Failure::Mirror(format!(
                "{name} does not match the manifest's SHA-256"
            )));
        }
        file.sync_all().map_err(io)
    });
    drop(file);
    match checked {
        Ok(()) => fs::rename(&partial, &path).map_err(io),
        Err(failure) => {
            let _ = fs::remove_file(&partial);
            Err(failure)
        }
    }
}

/// GET `name` under `mirror`, passing the body to `sink` piece by piece and
/// refusing more than `max_len` bytes.
async fn get(
    client: &reqwest::Client,
    mirror: &reqwest::Url,
    name: &str,
    max_len: u64,
    cancel: &AtomicBool,
    mut sink: impl FnMut(&[u8]),
) -> Result<(), Failure> {
    let mirror_err = |err: reqwest::Error| Failure::Mirror(err.without_url().to_string());
    let url = mirror
        .join(name)
        .map_err(|err| Failure::Mirror(format!("bad file URL ({err})")))?;
    let mut response = client.get(url).send().await.map_err(mirror_err)?;
    if !response.status().is_success() {
        return Err(Failure::Mirror(format!(
            "{name}: HTTP {}",
            response.status()
        )));
    }
    if response.content_length().is_some_and(|len| len > max_len) {
        return Err(Failure::Mirror(format!(
            "{name} is larger than the {max_len} bytes expected"
        )));
    }
    let mut total = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(Failure::Cancelled);
        }
        let Some(piece) = response.chunk().await.map_err(mirror_err)? else {
            return Ok(());
        };
        total += piece.len() as u64;
        if total > max_len {
            return Err(Failure::Mirror(format!(
                "{name} is larger than the {max_len} bytes expected"
            )));
        }
        sink(&piece);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sprout_pack::test_support::write_pack;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// What the test server does with one path.
    #[derive(Clone)]
    enum Fault {
        NotFound,
        /// Flip the last byte.
        Tamper,
        /// Send the headers for the full file, then close after this many
        /// bytes.
        CloseAfter(usize),
        /// Append bytes past the real end.
        Oversize(usize),
    }

    /// A minimal HTTP/1.1 server over a folder, for the download tests.
    struct TestServer {
        base: String,
        requests: Arc<Mutex<Vec<String>>>,
        faults: Arc<Mutex<HashMap<String, Fault>>>,
    }

    impl TestServer {
        async fn start(root: PathBuf) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}/pack/", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let faults: Arc<Mutex<HashMap<String, Fault>>> = Arc::default();
            let (req_log, fault_map) = (requests.clone(), faults.clone());
            tokio::spawn(async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        return;
                    };
                    let (req_log, fault_map, root) =
                        (req_log.clone(), fault_map.clone(), root.clone());
                    tokio::spawn(async move {
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            if sock.read(&mut byte).await.unwrap_or(0) == 0 {
                                return;
                            }
                            head.push(byte[0]);
                        }
                        let head = String::from_utf8_lossy(&head);
                        let path = head.split(' ').nth(1).unwrap_or("").to_string();
                        let name = path.trim_start_matches("/pack/").to_string();
                        req_log.lock().unwrap().push(name.clone());
                        let fault = fault_map.lock().unwrap().get(&name).cloned();
                        let body = fs::read(root.join(&name)).ok();
                        let (status, mut body) = match (body, &fault) {
                            (None, _) | (_, Some(Fault::NotFound)) => ("404 Not Found", Vec::new()),
                            (Some(body), _) => ("200 OK", body),
                        };
                        let mut send_len = body.len();
                        match fault {
                            Some(Fault::Tamper) if !body.is_empty() => {
                                let last = body.len() - 1;
                                body[last] ^= 0xff;
                            }
                            Some(Fault::Oversize(extra)) => body.extend(vec![0u8; extra]),
                            Some(Fault::CloseAfter(n)) => send_len = n.min(body.len()),
                            _ => {}
                        }
                        let header = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = sock.write_all(header.as_bytes()).await;
                        let _ = sock.write_all(&body[..send_len.min(body.len())]).await;
                        let _ = sock.shutdown().await;
                    });
                }
            });
            Self {
                base,
                requests,
                faults,
            }
        }

        fn fault(&self, name: &str, fault: Fault) {
            self.faults.lock().unwrap().insert(name.to_string(), fault);
        }

        fn clear_faults(&self) {
            self.faults.lock().unwrap().clear();
        }

        fn take_requests(&self) -> Vec<String> {
            std::mem::take(&mut *self.requests.lock().unwrap())
        }
    }

    const END: u32 = 250_000;

    /// A regtest pack in a folder, and a source pinned to its manifest.
    fn published_pack() -> (tempfile::TempDir, PackManifest, [u8; 32]) {
        let dir = tempfile::tempdir().unwrap();
        let manifest = write_pack(dir.path(), P2pNetwork::Regtest, END);
        let hash = manifest.sha256();
        (dir, manifest, hash)
    }

    fn source(hash: [u8; 32], mirrors: Vec<String>) -> PackSource {
        PackSource {
            network: P2pNetwork::Regtest,
            manifest_sha256: hash,
            end_height: END,
            mirrors,
        }
    }

    fn local_options() -> FetchOptions {
        FetchOptions {
            require_https: false,
            use_env_proxy: false,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
        }
    }

    async fn fetch(source: &PackSource, dir: &Path) -> ZeckResult<SproutPack> {
        fetch_pack(
            source,
            dir,
            &local_options(),
            &AtomicBool::new(false),
            |_| {},
        )
        .await
    }

    fn chunk_names(manifest: &PackManifest) -> Vec<String> {
        (0..manifest.chunks.len()).map(chunk_file_name).collect()
    }

    #[tokio::test]
    async fn downloads_a_pack_that_opens_and_verifies() {
        let (published, manifest, hash) = published_pack();
        let server = TestServer::start(published.path().to_path_buf()).await;
        let out = tempfile::tempdir().unwrap();
        let mut last = None;
        let pack = fetch_pack(
            &source(hash, vec![server.base.clone()]),
            out.path(),
            &local_options(),
            &AtomicBool::new(false),
            |p| last = Some(p),
        )
        .await
        .unwrap();
        assert_eq!(pack.manifest_sha256(), hash);
        pack.verify_all(|_| {}).unwrap();
        let last = last.unwrap();
        assert_eq!(last.chunks_done, manifest.chunks.len());
        assert_eq!(last.bytes_done, last.bytes_total);
        assert_eq!(last.bytes_total, manifest.total_bytes());
        let mut expected = vec![MANIFEST_FILE.to_string()];
        expected.extend(chunk_names(&manifest));
        assert_eq!(server.take_requests(), expected);
    }

    #[tokio::test]
    async fn a_manifest_that_is_not_pinned_is_refused_before_any_chunk() {
        let (published, _, hash) = published_pack();
        let server = TestServer::start(published.path().to_path_buf()).await;
        let mut wrong = hash;
        wrong[0] ^= 1;
        let out = tempfile::tempdir().unwrap();
        let err = fetch(&source(wrong, vec![server.base.clone()]), out.path())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("manifest"), "{err}");
        assert_eq!(server.take_requests(), vec![MANIFEST_FILE.to_string()]);
        assert!(!out.path().join(MANIFEST_FILE).exists());
    }

    #[tokio::test]
    async fn an_oversize_manifest_is_refused() {
        let (published, _, hash) = published_pack();
        let server = TestServer::start(published.path().to_path_buf()).await;
        server.fault(
            MANIFEST_FILE,
            Fault::Oversize(MAX_MANIFEST_BYTES as usize + 1),
        );
        let out = tempfile::tempdir().unwrap();
        assert!(fetch(&source(hash, vec![server.base.clone()]), out.path())
            .await
            .is_err());
        assert_eq!(server.take_requests(), vec![MANIFEST_FILE.to_string()]);
    }

    #[tokio::test]
    async fn a_tampered_chunk_is_not_kept() {
        let (published, manifest, hash) = published_pack();
        let server = TestServer::start(published.path().to_path_buf()).await;
        let bad = chunk_file_name(1);
        server.fault(&bad, Fault::Tamper);
        let out = tempfile::tempdir().unwrap();
        let err = fetch(&source(hash, vec![server.base.clone()]), out.path())
            .await
            .unwrap_err();
        assert!(err.to_string().contains(&bad), "{err}");
        assert!(!out.path().join(&bad).exists());
        assert!(!out.path().join(format!("{bad}.partial")).exists());
        // The chunk before it was kept; the one after was never requested.
        assert!(out.path().join(chunk_file_name(0)).exists());
        let requests = server.take_requests();
        assert!(!requests.contains(&chunk_file_name(2)), "{requests:?}");
        assert!(manifest.chunks.len() > 2);
    }

    #[tokio::test]
    async fn a_chunk_longer_than_the_manifest_says_is_not_kept() {
        let (published, _, hash) = published_pack();
        let server = TestServer::start(published.path().to_path_buf()).await;
        server.fault(&chunk_file_name(0), Fault::Oversize(10));
        let out = tempfile::tempdir().unwrap();
        let err = fetch(&source(hash, vec![server.base.clone()]), out.path())
            .await
            .unwrap_err();
        assert!(err.to_string().contains(&chunk_file_name(0)), "{err}");
        assert!(!out.path().join(chunk_file_name(0)).exists());
    }

    #[tokio::test]
    async fn an_interrupted_download_resumes_from_the_missing_chunks() {
        let (published, manifest, hash) = published_pack();
        let server = TestServer::start(published.path().to_path_buf()).await;
        server.fault(&chunk_file_name(1), Fault::CloseAfter(1_000));
        let out = tempfile::tempdir().unwrap();
        let src = source(hash, vec![server.base.clone()]);
        assert!(fetch(&src, out.path()).await.is_err());
        server.take_requests();
        server.clear_faults();
        fetch(&src, out.path()).await.unwrap();
        // The manifest and chunk 0 were kept; only the rest is fetched again.
        let expected: Vec<String> = chunk_names(&manifest)[1..].to_vec();
        assert_eq!(server.take_requests(), expected);
    }

    #[tokio::test]
    async fn a_complete_cache_makes_no_requests() {
        let (published, _, hash) = published_pack();
        let server = TestServer::start(published.path().to_path_buf()).await;
        let out = tempfile::tempdir().unwrap();
        let src = source(hash, vec![server.base.clone()]);
        fetch(&src, out.path()).await.unwrap();
        server.take_requests();
        fetch(&src, out.path()).await.unwrap();
        assert!(server.take_requests().is_empty());
    }

    #[tokio::test]
    async fn a_corrupted_cached_chunk_is_downloaded_again() {
        let (published, _, hash) = published_pack();
        let server = TestServer::start(published.path().to_path_buf()).await;
        let out = tempfile::tempdir().unwrap();
        let src = source(hash, vec![server.base.clone()]);
        fetch(&src, out.path()).await.unwrap();
        server.take_requests();
        let path = out.path().join(chunk_file_name(2));
        let mut bytes = fs::read(&path).unwrap();
        bytes[100] ^= 0xff;
        fs::write(&path, bytes).unwrap();
        fetch(&src, out.path())
            .await
            .unwrap()
            .verify_all(|_| {})
            .unwrap();
        assert_eq!(server.take_requests(), vec![chunk_file_name(2)]);
    }

    #[tokio::test]
    async fn a_failing_mirror_falls_through_to_the_next() {
        let (published, _, hash) = published_pack();
        let broken = TestServer::start(published.path().to_path_buf()).await;
        let good = TestServer::start(published.path().to_path_buf()).await;
        broken.fault(MANIFEST_FILE, Fault::NotFound);
        broken.fault(&chunk_file_name(0), Fault::Tamper);
        let out = tempfile::tempdir().unwrap();
        // A mirror nobody listens on comes first.
        let dead = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}/pack/", l.local_addr().unwrap())
        };
        let src = source(hash, vec![dead, broken.base.clone(), good.base.clone()]);
        fetch(&src, out.path())
            .await
            .unwrap()
            .verify_all(|_| {})
            .unwrap();
    }

    #[tokio::test]
    async fn plain_http_mirrors_are_refused_when_https_is_required() {
        let (published, _, hash) = published_pack();
        let server = TestServer::start(published.path().to_path_buf()).await;
        let out = tempfile::tempdir().unwrap();
        let options = FetchOptions {
            require_https: true,
            ..local_options()
        };
        let err = fetch_pack(
            &source(hash, vec![server.base.clone()]),
            out.path(),
            &options,
            &AtomicBool::new(false),
            |_| {},
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("https"), "{err}");
        assert!(server.take_requests().is_empty());
    }

    #[tokio::test]
    async fn cancelling_stops_the_download() {
        let (published, _, hash) = published_pack();
        let server = TestServer::start(published.path().to_path_buf()).await;
        let out = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let err = fetch_pack(
            &source(hash, vec![server.base.clone()]),
            out.path(),
            &local_options(),
            &cancel,
            |p| {
                if p.chunks_done == 1 {
                    cancel.store(true, Ordering::Relaxed);
                }
            },
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("cancel"), "{err}");
        assert!(out.path().join(chunk_file_name(0)).exists());
        assert!(!out.path().join(chunk_file_name(2)).exists());
    }

    #[test]
    fn a_pack_is_downloaded_only_when_a_scan_would_read_it() {
        let end = PackSource::pinned(P2pNetwork::Mainnet).unwrap().end_height;
        // A fresh scan, or one resumed below the pack's end.
        assert!(pack_to_download(P2pNetwork::Mainnet, None).is_some());
        assert!(pack_to_download(P2pNetwork::Mainnet, Some(end - 1)).is_some());
        // A scan already at or past the end reads nothing from it.
        assert!(pack_to_download(P2pNetwork::Mainnet, Some(end)).is_none());
        // No pin, no download.
        assert!(pack_to_download(P2pNetwork::Testnet, None).is_none());
        assert!(pack_to_download(P2pNetwork::Regtest, None).is_none());
    }

    #[test]
    fn every_pinned_mirror_is_https_and_a_folder() {
        for pin in PINNED_PACKS {
            assert!(!pin.mirrors.is_empty());
            for mirror in pin.mirrors {
                assert!(mirror.starts_with("https://"), "{mirror}");
                assert!(mirror.ends_with('/'), "{mirror}");
            }
        }
    }

    #[test]
    fn the_cache_folder_is_named_by_the_manifest_hash() {
        let src = PackSource::pinned(P2pNetwork::Mainnet).unwrap();
        let dir = src.cache_dir(Path::new("/data"));
        assert_eq!(
            dir,
            Path::new("/data/sprout-packs").join(format!(
                "mainnet-{}-{}",
                src.end_height,
                to_hex(&src.manifest_sha256)
            ))
        );
    }
}
