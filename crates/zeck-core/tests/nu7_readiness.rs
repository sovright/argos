//! NU7 qualification. Parser fixtures contain no inputs, outputs or funds;
//! they prove wire compatibility, not consensus acceptance or spendability.
use std::io::Cursor;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::{BlockHeight, BranchId, Network, NetworkUpgrade, Parameters};

const NU7_BRANCH: u32 = 0x7719_0ad9;
const REGTEST_NU7_HEIGHT: u32 = 32_500;

#[test]
fn production_networks_select_the_real_nu7_branch_at_activation() {
    for (network, activation) in [
        (Network::MainNetwork, 3_543_405),
        (Network::TestNetwork, 4_465_026),
    ] {
        assert_eq!(
            network.activation_height(NetworkUpgrade::Nu7),
            Some(activation.into())
        );
        assert_eq!(
            u32::from(BranchId::for_height(&network, (activation - 1).into())),
            0x37a5_165b
        );
        for height in [activation, activation + 1] {
            assert_eq!(
                u32::from(BranchId::for_height(&network, height.into())),
                NU7_BRANCH
            );
        }
        assert!(!TxVersion::V4.valid_in_branch(BranchId::Nu7));
        assert!(TxVersion::V5.valid_in_branch(BranchId::Nu7));
        assert!(TxVersion::V6.valid_in_branch(BranchId::Nu7));
    }
}

#[test]
fn actual_builder_uses_40_block_expiry_before_nu7_and_120_after() {
    use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
    for (network, activation) in [
        (Network::MainNetwork, 3_543_405_u32),
        (Network::TestNetwork, 4_465_026_u32),
    ] {
        for (target, delta) in [
            (activation - 1, 40),
            (activation, 120),
            (activation + 1, 120),
        ] {
            let builder = Builder::new(
                network,
                target.into(),
                BuildConfig::Standard {
                    sapling_anchor: None,
                    orchard_anchor: None,
                    ironwood_anchor: None,
                    orchard_padding: BundlePadding::DEFAULT,
                    ironwood_padding: BundlePadding::DEFAULT,
                },
            );
            assert_eq!(
                builder.expiry_height(),
                BlockHeight::from_u32(target + delta)
            );
            // The supported explicit override remains authoritative.
            assert_eq!(
                builder
                    .with_expiry_height((target + 7).into())
                    .expiry_height(),
                BlockHeight::from_u32(target + 7)
            );
        }
    }
}

/// Creation and serialization support is necessary for imported Sapling,
/// but an empty PCZT does not establish signing or node acceptance.
#[test]
fn pczt_creator_and_encoding_preserve_the_real_nu7_branch() {
    let created =
        pczt::roles::creator::Creator::new(NU7_BRANCH, REGTEST_NU7_HEIGHT + 120, 1, None, None)
            .unwrap()
            .build()
            .unwrap();
    assert_eq!(*created.global().consensus_branch_id(), NU7_BRANCH);
    assert_eq!(*created.global().tx_version(), 6);
    let encoded = created.serialize().unwrap();
    let parsed = pczt::Pczt::parse(&encoded).unwrap();
    assert_eq!(*parsed.global().consensus_branch_id(), NU7_BRANCH);
    assert_eq!(*parsed.global().expiry_height(), REGTEST_NU7_HEIGHT + 120);
    assert!(pczt::roles::creator::Creator::new(
        0xffff_ffff,
        REGTEST_NU7_HEIGHT + 120,
        1,
        None,
        None
    )
    .is_err());
}

/// Independent literal wire encoding: overwintered version, version group,
/// embedded branch, lock time, expiry, then empty bundle counts. In particular
/// NU7 does not append an experimental ZIP 233 amount to the v6 header.
fn empty_wire_transaction(version: TxVersion, branch: u32) -> Vec<u8> {
    let (header, group, bundle_counts) = match version {
        TxVersion::V5 => (0x8000_0005_u32, 0x26a7_270a_u32, 5),
        TxVersion::V6 => (0x8000_0006_u32, 0xd884_b698_u32, 6),
        _ => unreachable!(),
    };
    let mut bytes = Vec::new();
    for field in [header, group, branch, 0, REGTEST_NU7_HEIGHT + 120] {
        bytes.extend_from_slice(&field.to_le_bytes());
    }
    bytes.resize(bytes.len() + bundle_counts, 0);
    bytes
}

#[test]
fn nu7_v5_and_v6_wire_bytes_parse_and_roundtrip_without_placeholder_branch() {
    for version in [TxVersion::V5, TxVersion::V6] {
        let bytes = empty_wire_transaction(version, NU7_BRANCH);
        let mut reader = Cursor::new(&bytes);
        // v5/v6 carry their own branch. A historical caller hint must not
        // override that branch or silently reinterpret a future transaction.
        let parsed =
            Transaction::read(&mut reader, BranchId::Canopy).expect("NU7 wire transaction");
        assert_eq!(reader.position(), bytes.len() as u64);
        assert_eq!(parsed.version(), version);
        assert_eq!(u32::from(parsed.consensus_branch_id()), NU7_BRANCH);
        assert_eq!(
            parsed.expiry_height(),
            BlockHeight::from_u32(REGTEST_NU7_HEIGHT + 120)
        );
        assert!(parsed.sprout_bundle().is_none());
        let mut roundtrip = Vec::new();
        parsed.write(&mut roundtrip).unwrap();
        assert_eq!(roundtrip, bytes);
        assert!(Transaction::read(
            &empty_wire_transaction(version, 0xffff_ffff)[..],
            BranchId::Nu7
        )
        .is_err());
        assert!(Transaction::read(&bytes[..bytes.len() - 1], BranchId::Nu7).is_err());
    }
}

#[cfg(feature = "argos-network")]
fn qualified_params_at(height: u32) -> argos_core::workspace::ArgosParams {
    let mut local = argos_core::workspace::regtest_local_network();
    local.nu7 = Some(height.into());
    argos_core::workspace::ArgosParams::Regtest(local)
}

#[cfg(feature = "argos-network")]
#[test]
fn qualified_schedule_crosses_nu7_without_changing_legacy_fixtures() {
    use argos_core::workspace::ArgosParams;
    assert_eq!(
        ArgosParams::regtest_all_active().activation_height(NetworkUpgrade::Nu7),
        None
    );
    for height in [
        REGTEST_NU7_HEIGHT - 1,
        REGTEST_NU7_HEIGHT,
        REGTEST_NU7_HEIGHT + 1,
    ] {
        assert_eq!(
            u32::from(BranchId::for_height(
                &qualified_params_at(REGTEST_NU7_HEIGHT),
                height.into()
            )),
            if height < REGTEST_NU7_HEIGHT {
                0x37a5_165b
            } else {
                NU7_BRANCH
            }
        );
    }
}

#[cfg(feature = "argos-network")]
#[test]
fn wallet_account_and_scan_queue_survive_reopen_across_activation() {
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use secrecy::SecretVec;
    use zcash_client_backend::data_api::{
        chain::ChainState, AccountBirthday, WalletRead, WalletWrite,
    };
    use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, WalletDb};
    use zcash_primitives::block::BlockHash;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.sqlite");
    let params = qualified_params_at(REGTEST_NU7_HEIGHT);
    let seed = SecretVec::new(vec![0x42; 64]); // public synthetic identity, no value
    let account_id = {
        let mut db = WalletDb::for_path(&path, params, SystemClock, UnwrapErr(SysRng)).unwrap();
        init_wallet_db(&mut db, Some(SecretVec::new(vec![0x42; 64]))).unwrap();
        let birthday = AccountBirthday::from_parts(
            ChainState::empty((REGTEST_NU7_HEIGHT - 2).into(), BlockHash([0; 32])),
            None,
        );
        let (account, _) = db
            .create_account("NU7 reopen qualification", &seed, &birthday, None)
            .unwrap();
        db.update_chain_tip((REGTEST_NU7_HEIGHT - 1).into())
            .unwrap();
        account
    };
    for tip in [REGTEST_NU7_HEIGHT, REGTEST_NU7_HEIGHT + 1] {
        let mut db = WalletDb::for_path(&path, params, SystemClock, UnwrapErr(SysRng)).unwrap();
        init_wallet_db(&mut db, Some(SecretVec::new(vec![0x42; 64]))).unwrap();
        db.update_chain_tip(tip.into()).unwrap();
        assert_eq!(db.get_account_ids().unwrap(), vec![account_id]);
        assert!(db.get_account(account_id).unwrap().is_some());
        assert!(!db.suggest_scan_ranges().unwrap().is_empty());
    }
}

/// This fixture was created by the released Argos pre-NU7 SDK family, not by
/// the SDK under test. Copy first: the retained fixture must never be migrated
/// in place. See tests/regtest/legacy-wallet-db/README.md for reproduction.
#[test]
fn pre_nu7_database_migrates_without_losing_account_or_scan_work() {
    use rand::{rand_core::UnwrapErr, rngs::SysRng};
    use secrecy::SecretVec;
    use zcash_client_backend::data_api::{Account, WalletRead, WalletWrite};
    use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, WalletDb};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy-wallet.sqlite");
    std::fs::write(
        &path,
        include_bytes!("../../../tests/regtest/legacy-wallet-db/pre-nu7.sqlite"),
    )
    .unwrap();
    let before = rusqlite::Connection::open(&path).unwrap();
    let migrations_before: u64 = before
        .query_row("SELECT count(*) FROM schemer_migrations", [], |r| r.get(0))
        .unwrap();
    let original_ufvk: String = before
        .query_row("SELECT ufvk FROM accounts", [], |r| r.get(0))
        .unwrap();
    let original_uuid: Vec<u8> = before
        .query_row("SELECT uuid FROM accounts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(migrations_before, 57, "retained pre-NU7 schema fixture");
    drop(before);
    let mut db =
        WalletDb::for_path(&path, Network::TestNetwork, SystemClock, UnwrapErr(SysRng)).unwrap();
    init_wallet_db(&mut db, Some(SecretVec::new(vec![0x42; 64]))).unwrap();
    let ids = db.get_account_ids().unwrap();
    assert_eq!(ids.len(), 1);
    let account = db.get_account(ids[0]).unwrap().unwrap();
    assert_eq!(account.name(), Some("pre-NU7 public fixture"));
    let ufvk_before_reopen = account
        .ufvk()
        .unwrap()
        .encode(&Network::TestNetwork)
        .unwrap();
    assert_eq!(ufvk_before_reopen, original_ufvk);
    assert!(!db.suggest_scan_ranges().unwrap().is_empty());
    db.update_chain_tip(BlockHeight::from_u32(4_465_027))
        .unwrap();
    drop(db);
    let after = rusqlite::Connection::open(&path).unwrap();
    let migrations_after: u64 = after
        .query_row("SELECT count(*) FROM schemer_migrations", [], |r| r.get(0))
        .unwrap();
    assert!(migrations_after >= migrations_before);
    assert_eq!(
        after
            .query_row("SELECT uuid FROM accounts", [], |r| r.get::<_, Vec<u8>>(0))
            .unwrap(),
        original_uuid
    );
    assert_eq!(
        after
            .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "ok"
    );
    drop(after);
    let mut db =
        WalletDb::for_path(&path, Network::TestNetwork, SystemClock, UnwrapErr(SysRng)).unwrap();
    init_wallet_db(&mut db, Some(SecretVec::new(vec![0x42; 64]))).unwrap();
    assert_eq!(db.get_account_ids().unwrap(), ids);
    assert_eq!(
        db.get_account(ids[0])
            .unwrap()
            .unwrap()
            .ufvk()
            .unwrap()
            .encode(&Network::TestNetwork)
            .unwrap(),
        ufvk_before_reopen
    );
}

#[cfg(feature = "argos-network")]
fn private_node_rpc(method: &str, params: serde_json::Value) -> serde_json::Value {
    // Fixed endpoint: this qualification test can never select a public node.
    let output = std::process::Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "120",
            "-H",
            "Content-Type: application/json",
            "--data",
        ])
        .arg(
            serde_json::json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params})
                .to_string(),
        )
        .arg("http://127.0.0.1:18262")
        .output()
        .expect("curl installed");
    assert!(
        output.status.success(),
        "private node {method}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(reply["error"].is_null(), "{method}: {reply}");
    reply["result"].clone()
}

/// A live gate, never counted as a funded sweep or PCZT acceptance test.
/// The node must accept and mine synthetic regtest coinbase blocks across
/// the real configured consensus boundary. This is not a funded sweep.
#[cfg(feature = "argos-network")]
#[test]
#[ignore = "requires nu7-fast profile at height 9..11; mines any missing private blocks through 11"]
fn private_node_mines_and_parses_before_at_after_nu7() {
    use zcash_primitives::block::Block;
    const FAST_ACTIVATION: u32 = 10;
    let initial_tip = private_node_rpc("getblockcount", serde_json::json!([]))
        .as_u64()
        .unwrap() as u32;
    assert!((FAST_ACTIVATION - 1..=FAST_ACTIVATION + 1).contains(&initial_tip),
        "run ARGOS_NU7_PROFILE=fast tests/regtest/nu7.sh before first; this test never rewinds or deletes retained state");
    for height in [FAST_ACTIVATION - 1, FAST_ACTIVATION, FAST_ACTIVATION + 1] {
        if height > initial_tip {
            private_node_rpc("generate", serde_json::json!([1]));
        }
        let info = private_node_rpc("getblockchaininfo", serde_json::json!([]));
        assert_eq!(info["chain"], "test"); // Zebra uses the test chain name for Regtest.
        assert_eq!(
            info["upgrades"]["77190ad9"]["activationheight"],
            FAST_ACTIVATION
        );
        assert_eq!(info["blocks"], height.max(initial_tip));
        let hash = private_node_rpc("getblockhash", serde_json::json!([height]));
        let hex = private_node_rpc("getblock", serde_json::json!([hash, 0]));
        let hex = hex.as_str().unwrap();
        let raw: Vec<_> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let mut cursor = Cursor::new(&raw);
        let block = Block::read(&mut cursor, &qualified_params_at(FAST_ACTIVATION))
            .expect("real node block parses");
        assert_eq!(cursor.position(), raw.len() as u64);
        assert!(!block.vtx().is_empty());
        let expected_branch = if height < FAST_ACTIVATION {
            0x37a5_165b
        } else {
            NU7_BRANCH
        };
        for tx in block.vtx() {
            assert_eq!(u32::from(tx.consensus_branch_id()), expected_branch);
        }
        eprintln!("[nu7-node] accepted block height={height} branch={expected_branch:08x} transactions={}", block.vtx().len());
    }
}

/// The proxy gate is separate from block acceptance so an emulator/runtime
/// failure cannot erase the node's independently retained boundary evidence.
#[cfg(feature = "argos-network")]
#[tokio::test]
#[ignore = "requires nu7-fast node at height 11 and private proxy on 9087 or native 9088"]
async fn private_proxy_serves_the_accepted_nu7_compact_block() {
    use zcash_client_backend::proto::service::{
        compact_tx_streamer_client::CompactTxStreamerClient, BlockId, Empty,
    };
    let endpoint = std::env::var("ARGOS_NU7_LIGHTWALLETD_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:9087".to_owned());
    assert!(
        matches!(
            endpoint.as_str(),
            "http://127.0.0.1:9087" | "http://127.0.0.1:9088"
        ),
        "qualification only permits the dedicated private proxy endpoints"
    );
    let mut client = CompactTxStreamerClient::connect(endpoint)
        .await
        .expect("private lightwalletd proxy");
    for attempt in 0..30 {
        let info = client.get_lightd_info(Empty {}).await.unwrap().into_inner();
        if info.block_height >= 11 {
            assert_eq!(info.consensus_branch_id.to_lowercase(), "77190ad9");
            let block = client
                .get_block(BlockId {
                    height: 10,
                    hash: vec![],
                })
                .await
                .unwrap()
                .into_inner();
            assert_eq!(block.height, 10);
            eprintln!(
                "[nu7-proxy] served NU7 compact block height={} branch={}",
                block.height, info.consensus_branch_id
            );
            return;
        }
        assert!(attempt < 29, "private proxy did not ingest NU7 blocks");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
