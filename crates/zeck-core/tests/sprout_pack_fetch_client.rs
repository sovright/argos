//! The download's HTTP client must build in a process where nothing else has
//! installed a rustls crypto provider. reqwest is built without one of its own
//! and panics if none is installed, so this runs as its own test binary: a
//! fresh process, unlike the library's unit tests.

use argos_core::sprout_pack_fetch::{http_client, FetchOptions};

#[test]
fn the_client_builds_in_a_fresh_process() {
    http_client(&FetchOptions::default()).expect("client builds");
}

/// Downloads the mainnet pack from the live mirrors with production settings
/// and verifies it. About 1.3 GB, so ignored by default; run it after
/// changing a mirror:
/// `ARGOS_PACK_DIR=<empty dir> cargo test -p argos-core --test
/// sprout_pack_fetch_client -- --ignored`.
#[test]
#[ignore]
fn the_live_mirrors_serve_the_pinned_mainnet_pack() {
    use argos_core::p2p::wire::P2pNetwork;
    use argos_core::sprout_pack_fetch::{fetch_pack, PackSource};
    use std::sync::atomic::AtomicBool;

    let dir = std::env::var_os("ARGOS_PACK_DIR").expect("set ARGOS_PACK_DIR to an empty folder");
    let source = PackSource::pinned(P2pNetwork::Mainnet).expect("a mainnet pin");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let pack = runtime
        .block_on(fetch_pack(
            &source,
            std::path::Path::new(&dir),
            &FetchOptions::default(),
            &AtomicBool::new(false),
            |_| {},
        ))
        .expect("download");
    pack.verify_all(|_| {}).expect("pack verifies");
}
