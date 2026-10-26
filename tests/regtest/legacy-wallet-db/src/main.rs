//! Generates only a synthetic, empty pre-NU7 wallet database. No network access.
use rand_core::OsRng;
use secrecy::SecretVec;
use zcash_client_backend::data_api::{chain::ChainState, AccountBirthday, WalletWrite};
use zcash_client_sqlite::{util::SystemClock, wallet::init::init_wallet_db, WalletDb};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Network};

fn main() {
    let destination = std::env::args().nth(1).expect("output database path");
    assert!(
        !std::path::Path::new(&destination).exists(),
        "refuse to overwrite a database"
    );
    let mut db =
        WalletDb::for_path(&destination, Network::TestNetwork, SystemClock, OsRng).unwrap();
    init_wallet_db(&mut db, Some(SecretVec::new(vec![0x42; 64]))).unwrap();
    let birthday = AccountBirthday::from_parts(
        ChainState::empty(BlockHeight::from_u32(4_465_024), BlockHash([0; 32])),
        None,
    );
    db.create_account(
        "pre-NU7 public fixture",
        &SecretVec::new(vec![0x42; 64]),
        &birthday,
        Some("synthetic-0x42-not-a-wallet"),
    )
    .unwrap();
    db.update_chain_tip(BlockHeight::from_u32(4_465_025))
        .unwrap();
    println!("created empty pre-NU7 SDK database at {destination}");
}
