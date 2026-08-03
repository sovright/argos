//! `argos-regtest-funder` — test-only binary that funds a seed on the regtest
//! harness.
//!
//! ## Why this exists
//!
//! The harness node used to be zcashd, and `setup.sh` funded the test seed with
//! `zcash-cli sendtoaddress`. The Ironwood (NU6.3) work forced the node to
//! Zebra — `UPGRADE_NU6_3` appears nowhere in zcash/zcash, so a zcashd chain
//! can never activate Ironwood — and **Zebra has no wallet**: no
//! `sendtoaddress`, no `getnewaddress`. Something has to replace that RPC.
//!
//! ## Why it funds with shielded coinbase
//!
//! The obvious route — mine transparent coinbase to a throwaway account and
//! shield it to the test seed with `propose_shielding_coinbase` — does not
//! work from a lightwalletd-backed wallet, and the reason is worth recording.
//!
//! Spending transparent coinbase requires `CoinbaseFilter::CoinbaseOnly`,
//! which selects only outputs the wallet *knows* are coinbase. That knowledge
//! is the transaction's index within its block: index 0 means coinbase.
//! Argos discovers transparent outputs through the `GetAddressUtxos` RPC,
//! whose reply carries the txid, output index, value and height — but not the
//! transaction's position in the block. So `tx_index` lands NULL in the wallet
//! database, every output is conservatively treated as non-coinbase, and the
//! proposal fails with "Insufficient balance (have 0)" while the wallet is
//! visibly holding hundreds of ZEC. Verified directly against the harness DB.
//!
//! Shielded coinbase (ZIP 213) sidesteps the whole problem. Zebra's
//! `generatetoaddress` accepts a shielded recipient, and a shielded coinbase
//! note is spendable as an ordinary note once mature — no shielding step, no
//! funder wallet, no proving. The test seed simply receives notes.
//!
//! That also makes for a better post-activation sweep test than transparent
//! funding would: it forces shielded pool selection, Ironwood included.
//! It does not reproduce the transparent UTXOs the older network-resilience
//! tests were written against — see README.md.
//!
//! ## CLI
//!
//! ```bash
//! argos-regtest-funder \
//!     --zebra-rpc-url <url> \
//!     [--blocks <n>]           # coinbase blocks paid to the seed (default 4)
//!     [--maturity-blocks <n>]  # blocks mined afterwards (default 100)
//!     [--print-address-only]   # derive and print, mine nothing
//!     [--address <addr>]       # fund this address instead of the seed's
//!                              # shielded one (--t-addr is a legacy alias)
//!     [--print-fixture-addresses]  # print the golden wallet fixture's
//!                              # Sapling and transparent addresses, then exit
//! ```
//!
//! ## Why `--t-addr` exists despite the section above
//!
//! The shielded-coinbase reasoning above is about `zcash_client_sqlite`'s
//! UTXO selection, which needs to know an output is coinbase and cannot.
//! Transparent-only recovery (`argos_core::transparent_recovery`) never
//! touches the wallet database — it reads `GetAddressUtxos` and drives the
//! transaction builder directly — so that limitation does not apply to it,
//! and it needs a funded transparent address to test against.
//!
//! A consensus rule does still apply: a transaction spending transparent
//! coinbase must have no transparent outputs. A transparent-only sweep is
//! N transparent inputs to exactly one Sapling output with no change, so it
//! satisfies that by construction.
//!
//! The seed to fund is read from `ARGOS_REGTEST_FUND_SEED`.
//!
//! ## stdout schema (one JSON object per line, flushed after each)
//!
//! ```text
//! {"event":"fund_address","address":"zregtestsapling1..."}
//! {"event":"mined","blocks":N,"height":N}
//! {"event":"funded","blocks_to_seed":N,"height":N}
//! {"event":"error","message":"..."}
//! ```

#![cfg(feature = "argos-network")]

use std::io::Write;
use std::process::ExitCode;

// A `[[bin]]` target cannot `use` the integration tests' `common` module, so
// pull in just the shared key definition by path. Keeping one definition is
// the point: the funder and the test must agree on the address.
#[path = "../common/standalone_transparent.rs"]
mod standalone_transparent;

use argos_core::{
    workspace::{consensus_network, regtest_local_network, set_regtest_consensus_params},
    ZeckNetwork,
};
use secrecy::SecretString;
use serde::Serialize;

/// Coinbase maturity on Zcash. A coinbase note cannot be spent until this many
/// blocks sit on top of it, so the harness always mines past it before any
/// test tries to sweep.
const COINBASE_MATURITY: u32 = 100;

/// Four blocks gives the funded seed several independent notes rather than one
/// large one, so a sweep has to select across notes rather than trivially
/// spending a single input.
const DEFAULT_FUNDING_BLOCKS: u32 = 4;

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Event<'a> {
    FundAddress {
        address: &'a str,
    },
    /// The golden wallet fixture's addresses, so setup.sh can fund the
    /// imported-wallet tests without duplicating the derivation.
    ///
    /// `standalone_transparent` is not from the fixture: it belongs to the
    /// transparent-only test, which needs an address the imported sweep
    /// will not drain. See `tests/common/standalone_transparent.rs`.
    FixtureAddresses {
        sapling: String,
        transparent: String,
        standalone_transparent: String,
    },
    Mined {
        blocks: u32,
        height: u64,
    },
    Funded {
        blocks_to_seed: u32,
        height: u64,
    },
}

fn emit(event: &Event<'_>) {
    let line = serde_json::to_string(event).expect("helper events are always serializable");
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

struct Args {
    zebra_rpc_url: String,
    blocks: u32,
    maturity_blocks: u32,
    print_address_only: bool,
    /// When set, mine coinbase to this address instead of the seed's
    /// shielded one. Any address Zebra accepts as a miner address.
    t_addr: Option<String>,
    /// Print the golden wallet fixture's addresses and exit.
    print_fixture_addresses: bool,
}

/// Emit the golden wallet fixture's addresses.
///
/// They come from the fixture rather than being generated, because the
/// imported-wallet tests import that exact file — funding any other
/// address would leave them looking at an empty wallet.
fn print_fixture_addresses() {
    use argos_core::imported::{
        encode_transparent_address, imported_transparent_keys, parse_sapling_extsk,
    };
    use secrecy::ExposeSecret;
    use zcash_keys::encoding::AddressCodec;

    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../argos-wallet-import/tests/fixtures/sprout-plaintext.dat"
    );
    let bytes = std::fs::read(path).expect("golden fixture must exist");
    let keys = argos_core::argos_wallet_import::import_wallet_file(&bytes, None)
        .expect("golden fixture must import");

    let extsk = parse_sapling_extsk(
        keys.sapling
            .first()
            .expect("fixture must hold a Sapling key")
            .extsk
            .expose_secret(),
    )
    .expect("the fixture Sapling key must parse");
    let (_, payment_address) = extsk.to_diversifiable_full_viewing_key().default_address();

    let transparent = imported_transparent_keys(&keys).expect("transparent keys must resolve");
    let params = consensus_network(ZeckNetwork::Testnet);

    emit(&Event::FixtureAddresses {
        sapling: payment_address.encode(&params),
        transparent: encode_transparent_address(
            &transparent
                .first()
                .expect("fixture must hold a transparent key")
                .address,
            ZeckNetwork::Testnet,
        ),
        standalone_transparent: encode_transparent_address(
            &standalone_transparent::standalone_transparent_key().address,
            ZeckNetwork::Testnet,
        ),
    });
}

fn parse_args() -> Args {
    let mut zebra_rpc_url = None;
    let mut blocks = DEFAULT_FUNDING_BLOCKS;
    let mut maturity_blocks = COINBASE_MATURITY;
    let mut print_address_only = false;
    let mut t_addr = None;
    let mut print_fixture_addresses = false;

    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || {
            argv.next()
                .unwrap_or_else(|| panic!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--zebra-rpc-url" => zebra_rpc_url = Some(value()),
            "--blocks" => blocks = value().parse().expect("--blocks must be a u32"),
            "--maturity-blocks" => {
                maturity_blocks = value().parse().expect("--maturity-blocks must be a u32")
            }
            "--print-address-only" => print_address_only = true,
            "--address" | "--t-addr" => t_addr = Some(value()),
            "--print-fixture-addresses" => print_fixture_addresses = true,
            other => panic!("unrecognized argument {other}"),
        }
    }

    Args {
        zebra_rpc_url: zebra_rpc_url.expect("--zebra-rpc-url is required"),
        blocks,
        maturity_blocks,
        print_address_only,
        t_addr,
        print_fixture_addresses,
    }
}

/// Minimal JSON-RPC call against Zebra. Zebra runs with cookie auth disabled
/// (see `zebrad-regtest.toml`), so no credentials are sent.
async fn zebra_rpc(url: &str, method: &str, params: serde_json::Value) -> serde_json::Value {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let response = post_json(url, &body).await;
    if let Some(error) = response.get("error").filter(|e| !e.is_null()) {
        panic!("zebra RPC {method} failed: {error}");
    }
    response
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

/// Hand-rolled HTTP POST so the helper does not pull an HTTP client crate in
/// for three calls. `tonic` is already present but speaks gRPC, not JSON-RPC.
async fn post_json(url: &str, body: &serde_json::Value) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let stripped = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = match stripped.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (stripped, "/".to_owned()),
    };

    let payload = serde_json::to_vec(body).expect("request body is serializable");
    let mut stream = tokio::net::TcpStream::connect(host_port)
        .await
        .unwrap_or_else(|err| panic!("connecting to zebra at {host_port}: {err}"));

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write headers");
    stream.write_all(&payload).await.expect("write body");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read response");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let json_start = text
        .find("\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or_else(|| panic!("malformed HTTP response from zebra: {text}"));
    serde_json::from_str(text[json_start..].trim())
        .unwrap_or_else(|err| panic!("zebra returned non-JSON ({err}): {}", &text[json_start..]))
}

async fn block_count(url: &str) -> u64 {
    zebra_rpc(url, "getblockcount", serde_json::json!([]))
        .await
        .as_u64()
        .expect("getblockcount returns a number")
}

/// `argos show-keys` emits testnet-encoded addresses (`ztestsapling1...`), but
/// Zebra validates miner addresses against the Regtest parameter set and
/// rejects the testnet HRP outright. The underlying receiver is identical;
/// only the human-readable prefix differs, so decode under testnet and
/// re-encode under regtest.
fn regtest_encoded_sapling_address(seed: &SecretString) -> String {
    use zcash_keys::address::Address;

    let accounts = argos_core::derive_accounts(seed, ZeckNetwork::Testnet, 1)
        .unwrap_or_else(|err| panic!("deriving accounts for the seed to fund: {err}"));
    let testnet_encoded = &accounts[0].sapling_address;

    let address = Address::decode(
        &zcash_protocol::consensus::Network::TestNetwork,
        testnet_encoded,
    )
    .unwrap_or_else(|| panic!("argos produced an undecodable sapling address: {testnet_encoded}"));

    address.encode(&consensus_network(ZeckNetwork::Testnet))
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = parse_args();
    // Printing fixture addresses needs no seed — it reads the golden
    // wallet file — so it must not be gated behind the seed requirement.
    let seed_env = std::env::var("ARGOS_REGTEST_FUND_SEED");

    // Must precede any address encoding: `consensus_network` only reports
    // regtest once these are installed, and without them the derived address
    // carries the testnet HRP that Zebra rejects.
    set_regtest_consensus_params(regtest_local_network())
        .expect("installing regtest consensus parameters");

    if args.print_fixture_addresses {
        print_fixture_addresses();
        return ExitCode::SUCCESS;
    }

    let seed = SecretString::new(
        seed_env.expect("ARGOS_REGTEST_FUND_SEED must be set to the mnemonic to fund"),
    );

    // `--t-addr` is taken verbatim: it comes from a test that derived it
    // from a raw key under regtest parameters, so re-encoding it here would
    // only risk disagreeing with the address the test will query
    // lightwalletd for.
    let address = match &args.t_addr {
        Some(t_addr) => t_addr.clone(),
        None => regtest_encoded_sapling_address(&seed),
    };
    emit(&Event::FundAddress { address: &address });

    if args.print_address_only {
        return ExitCode::SUCCESS;
    }

    // Coinbase paid to a shielded address is an ordinary note under ZIP 213,
    // so the funded seed needs no shielding step — only maturity.
    zebra_rpc(
        &args.zebra_rpc_url,
        "generatetoaddress",
        serde_json::json!([args.blocks, address]),
    )
    .await;
    emit(&Event::Mined {
        blocks: args.blocks,
        height: block_count(&args.zebra_rpc_url).await,
    });

    // Maturity blocks are paid to the node's configured miner_address, not to
    // the funded seed, so the seed's balance stays exactly `blocks` notes.
    if args.maturity_blocks > 0 {
        zebra_rpc(
            &args.zebra_rpc_url,
            "generate",
            serde_json::json!([args.maturity_blocks]),
        )
        .await;
        emit(&Event::Mined {
            blocks: args.maturity_blocks,
            height: block_count(&args.zebra_rpc_url).await,
        });
    }

    emit(&Event::Funded {
        blocks_to_seed: args.blocks,
        height: block_count(&args.zebra_rpc_url).await,
    });
    ExitCode::SUCCESS
}
