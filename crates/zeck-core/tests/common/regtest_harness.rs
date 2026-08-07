//! Rust-side fixture for the C2 integration tests.
//!
//! Reads the harness URL and funded test seed from environment variables
//! set by `tests/regtest/setup.sh`. Each integration test calls
//! `RegtestHarness::require()` at the top; if the env vars are absent the
//! test prints a clear "harness not running" message and panics — which is
//! intentionally caught by the `#[ignore]` tag on every C2 test so default
//! `cargo test` never sees the panic.
//!
//! See `tests/regtest/README.md` for the boot procedure.

use std::env;

/// Argos test seed (BIP-39 test vector — no real funds anywhere).
///
/// Matches the seed funded by `tests/regtest/setup.sh`. Centralised here so
/// the integration tests and the funding script agree on the same string.
pub const ARGOS_TEST_SEED: &str =
    "abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon art";

/// Environment variable holding the lightwalletd endpoint of the running
/// harness. Set by `tests/regtest/setup.sh`; consumed by every C2 test.
pub const ENV_LIGHTWALLETD_URL: &str = "ARGOS_REGTEST_LIGHTWALLETD_URL";

/// Environment variable holding the funded test seed's transparent address.
/// Set by `tests/regtest/setup.sh` after the funding `sendtoaddress`.
/// Optional — tests that only need the lightwalletd endpoint don't have to
/// require it.
pub const ENV_TEST_T_ADDR: &str = "ARGOS_REGTEST_TEST_T_ADDR";

/// A handle on the running regtest stack.
///
/// Construction is deliberately fail-loud: if the environment isn't set up,
/// calling `RegtestHarness::require()` panics with a message pointing to
/// `tests/regtest/README.md` so a contributor running `cargo test
/// --ignored` without the harness sees what to do next.
#[derive(Debug, Clone)]
pub struct RegtestHarness {
    lightwalletd_url: String,
    funded_t_addr: Option<String>,
}

impl RegtestHarness {
    /// Read the harness configuration from the environment, panicking if the
    /// required variables aren't set. Integration tests call this at the
    /// top of `#[test]` so a missing harness is loud and obvious — combined
    /// with `#[ignore]`, the panic stays out of CI.
    pub fn require() -> Self {
        let lightwalletd_url = env::var(ENV_LIGHTWALLETD_URL).unwrap_or_else(|_| {
            panic!(
                "{ENV_LIGHTWALLETD_URL} is not set. \
                 Boot the regtest harness (`cd tests/regtest && docker compose up -d && ./setup.sh`) \
                 and export the lightwalletd URL it prints. \
                 See tests/regtest/README.md.",
            )
        });
        // Install regtest activation heights before the caller derives a
        // branch ID, builds a transaction, or opens a workspace.
        //
        // This lives here rather than in individual tests because
        // `REGTEST_PARAMS` is a process-wide `OnceLock` and cargo runs a
        // test binary's tests as threads in one process. When only one test
        // installed the parameters, whether any *other* test saw them
        // depended on thread scheduling: a sweep could be signed for a
        // pre-NU5 branch and rejected by the node, or a scan could resolve
        // the wrong activation heights, entirely at random
        // (sovright/argos#186).
        //
        // Every regtest test calls `require()`, so installing here makes it
        // deterministic and impossible to forget in a new test. The
        // underlying setter is idempotent for an equal value, so repeated
        // calls across tests are fine.
        #[cfg(feature = "argos-network")]
        argos_core::workspace::set_regtest_consensus_params(
            argos_core::workspace::regtest_local_network(),
        )
        .expect("installing regtest consensus parameters");

        let funded_t_addr = env::var(ENV_TEST_T_ADDR).ok();
        Self {
            lightwalletd_url,
            funded_t_addr,
        }
    }

    /// The lightwalletd endpoint to pass to `RecoveryService::start_scan`'s
    /// `ScanConfig.lightwalletd_url`. Loopback-only (`http://localhost:9067`
    /// by default) and Argos's `validate_lightwalletd_endpoint` accepts the
    /// plaintext form because it's a loopback host.
    pub fn lightwalletd_url(&self) -> &str {
        &self.lightwalletd_url
    }

    /// The funded test seed's transparent address. Returns `None` if the
    /// optional env var wasn't exported (tests that only verify the scan
    /// side don't need it; tests that verify funding amounts do).
    pub fn funded_t_addr(&self) -> Option<&str> {
        self.funded_t_addr.as_deref()
    }

    /// The Argos test seed phrase. Same value as `ARGOS_TEST_SEED` —
    /// exposed as a method so future evolution (e.g. multiple test seeds
    /// for different scenarios) doesn't require changing every test's
    /// import.
    pub fn test_seed(&self) -> &'static str {
        ARGOS_TEST_SEED
    }
}

/// Zebra's JSON-RPC endpoint for the harness chain.
pub const ENV_ZEBRA_RPC_URL: &str = "ARGOS_REGTEST_ZEBRA_RPC_URL";

/// Minimal JSON-RPC call against Zebra.
///
/// Hand-rolled over TCP for the same reason the funder helper is: the test
/// tree carries no HTTP client dependency, and Zebra runs with cookie auth
/// disabled (see `zebrad-regtest.toml`), so no credentials are needed.
pub async fn zebra_rpc(method: &str, params: serde_json::Value) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let url = env::var(ENV_ZEBRA_RPC_URL)
        .unwrap_or_else(|_| "http://127.0.0.1:18232".to_owned());
    let host_port = url.strip_prefix("http://").unwrap_or(&url).to_owned();

    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    });
    let payload = serde_json::to_vec(&body).expect("serializable");

    let mut stream = tokio::net::TcpStream::connect(&host_port)
        .await
        .unwrap_or_else(|err| panic!("connecting to zebra at {host_port}: {err}"));
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(request.as_bytes()).await.expect("headers");
    stream.write_all(&payload).await.expect("body");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("response");
    let text = String::from_utf8_lossy(&raw);
    let json_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let parsed: serde_json::Value = serde_json::from_str(text[json_start..].trim())
        .unwrap_or_else(|err| panic!("zebra {method} returned unparseable body: {err}\n{text}"));

    if let Some(error) = parsed.get("error") {
        if !error.is_null() {
            panic!("zebra {method} failed: {error}");
        }
    }
    parsed
        .get("result")
        .cloned()
        .unwrap_or_else(|| panic!("zebra {method} returned no result: {parsed}"))
}

/// The treasury mnemonic, matching `tests/regtest/setup.sh`.
///
/// Distinct from [`ARGOS_TEST_SEED`] because sweep tests drain what they
/// test, and distinct from the miner seed (all-zoo/vote, in
/// `zebrad-regtest.toml`) because that seed's account-0 transparent address
/// *is* `miner_address` — a treasury on it collects one transparent output
/// per mined block, and every funding scan then walks all of them.
pub const ARGOS_TREASURY_SEED: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

/// Pay `zatoshis` from the treasury to the test seed's `account`, and mine it.
///
/// Sweep tests share the test seed and drain it, so which of them has funds
/// used to depend on the order `cargo test` happened to run them in — the
/// donation sweep failed with "sweep should have broadcast at least one
/// transaction" purely because an earlier test had swept the account first.
/// A test that needs funds should say so rather than inherit them.
///
/// This is only possible because funding no longer depends on coinbase: the
/// regtest subsidy is worthless by the heights ZIP 212 forces this harness
/// to, so before transfer-based funding there was nothing to top up from.
/// See `argos_core::regtest_funding`.
pub async fn fund_test_account(account: u32, zatoshis: u64) {
    let address = derive_test_address(account).await;
    fund_address(&address, zatoshis).await;
}

/// Derive one of the test seed's account addresses via the funder.
pub async fn derive_test_address(account: u32) -> String {
    use tokio::process::Command;

    let funder = env!("CARGO_BIN_EXE_argos-regtest-funder");
    let lightwalletd = env::var(ENV_LIGHTWALLETD_URL)
        .expect("ARGOS_REGTEST_LIGHTWALLETD_URL must be set to fund a test account");
    let zebra_rpc_url =
        env::var(ENV_ZEBRA_RPC_URL).unwrap_or_else(|_| "http://127.0.0.1:18232".to_owned());

    // Derive the destination from the seed under test, not the treasury.
    let derived = Command::new(funder)
        .args(["--zebra-rpc-url", &zebra_rpc_url])
        .args(["--account", &account.to_string()])
        .arg("--print-address-only")
        .env("ARGOS_REGTEST_FUND_SEED", ARGOS_TEST_SEED)
        .output()
        .await
        .expect("running the funder to derive a test address");
    let stdout = String::from_utf8_lossy(&derived.stdout);
    let address = stdout
        .split("\"address\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_else(|| {
            panic!("[regtest] could not parse a funding address from: {stdout}")
        })
        .to_owned();

    address
}

/// Pay any address from the treasury, and mine the payment.
///
/// The primitive behind [`fund_test_account`]. Exposed separately because not
/// everything the suite funds is an HD account of the test seed — the
/// transparent-only sweep spends a standalone key that no account owns.
pub async fn fund_address(address: &str, zatoshis: u64) {
    use tokio::process::Command;

    let funder = env!("CARGO_BIN_EXE_argos-regtest-funder");
    let lightwalletd = env::var(ENV_LIGHTWALLETD_URL)
        .expect("ARGOS_REGTEST_LIGHTWALLETD_URL must be set to fund an address");
    let zebra_rpc_url =
        env::var(ENV_ZEBRA_RPC_URL).unwrap_or_else(|_| "http://127.0.0.1:18232".to_owned());

    let funded = Command::new(funder)
        .args(["--zebra-rpc-url", &zebra_rpc_url])
        .args(["--lightwalletd-url", &lightwalletd])
        .args(["--transfer", &format!("{address}:{zatoshis}")])
        .env("ARGOS_REGTEST_FUND_SEED", ARGOS_TREASURY_SEED)
        .output()
        .await
        .expect("running the funder to pay a test address");
    // A "database is locked" here almost always means something else is
    // funding at the same time — a `setup.sh` still running, or tests without
    // `--test-threads=1`. Every funding call shares one treasury workspace,
    // and SQLite permits one writer. Say so, because the raw error points at
    // the wallet database and not at the concurrency that caused it.
    let stderr = String::from_utf8_lossy(&funded.stderr);
    assert!(
        funded.status.success(),
        "[regtest] treasury funding of {address} failed: {stderr}{}",
        if stderr.contains("database is locked") {
            "\n[regtest] the treasury workspace is held by another process —              check for a running setup.sh or a concurrent test, and re-run              with --test-threads=1"
        } else {
            ""
        }
    );

    // Confirm it: a scan reads compact blocks, so an unmined payment is
    // invisible to the test that just asked for it.
    zebra_rpc("generate", serde_json::json!([1])).await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
}

/// The birthday a test should scan the funded seed from.
///
/// `setup.sh` records the height it started funding at; everything the suite
/// spends was paid at or after it. Scanning from there instead of from genesis
/// is the difference between reading a few hundred blocks and reading the
/// ~32,000 empty ones below them — the harness has to mine that far for ZIP
/// 212, and before funding moved off coinbase the money was down at the
/// bottom, so height 1 was the only correct answer.
///
/// Falls back to 1 when the file is absent, which is both correct and slow:
/// an older `setup.sh`, or a chain funded some other way, still scans.
pub fn funding_birthday() -> u32 {
    let path = env::temp_dir().join("argos-regtest-funding-height");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .filter(|height| *height > 0)
        .unwrap_or(1)
}
