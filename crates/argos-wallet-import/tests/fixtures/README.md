# ZecWallet Lite network fixtures

These are no-funds, deterministic wallets written by `LightWallet::write` in the public upstream `zingolabs/zwl-lib` repository at commit `9ef78e9db5d58de19006e85738b041c25a5d501c`. The parser layout was checked against the same writer's `LightWallet::read` and `lib/src/lightwallet/{keys,walletokey,walletzkey,wallettkey}.rs` at that commit (`zwl-lib` is MIT licensed). `zingolabs/zewif-zwl` carries no licence and is not used as a reference. The seed is public test material and must never receive funds. Its exact 24-word phrase is:

> abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art

Reproduce on macOS or Linux with Rust 1.72.1 installed. Set `ARGOS` to your Argos checkout and `WORK` to any scratch directory:

```sh
export ARGOS="$(git rev-parse --show-toplevel)"   # run from inside the Argos checkout
export WORK="${TMPDIR:-/tmp}/zwl-lib-fixtures"
export ARGOS_FIXTURES="$ARGOS/crates/argos-wallet-import/tests/fixtures"
git clone https://github.com/zingolabs/zwl-lib.git "$WORK"
cd "$WORK"
git checkout 9ef78e9db5d58de19006e85738b041c25a5d501c
mkdir -p lib/examples
cat > lib/examples/generate_empty.rs <<'RS'
use zecwalletlitelib::lightclient::lightclient_config::LightClientConfig;
use zecwalletlitelib::lightwallet::LightWallet;
use zcash_primitives::consensus::{MainNetwork, TestNetwork, BlockHeight};
use zcash_primitives::transaction::TxId;
fn out(name: &str) -> String {
    format!("{}/{name}", std::env::var("ARGOS_FIXTURES").expect("set ARGOS_FIXTURES"))
}
const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
#[tokio::main]
async fn main() {
    let mut main = LightClientConfig::create_unconnected(MainNetwork, None);
    main.chain_name = "main".to_string();
    let wallet = LightWallet::new(main, Some(PHRASE.to_string()), 0, 0, 0).unwrap();
    let mut bytes = vec![];
    wallet.write(&mut bytes).await.unwrap();
    std::fs::write(out("zwl-mainnet-empty.dat"), bytes).unwrap();
    let mut test = LightClientConfig::create_unconnected(TestNetwork, None);
    test.chain_name = "test".to_string();
    let wallet = LightWallet::new(test, Some(PHRASE.to_string()), 0, 0, 0).unwrap();
    let mut bytes = vec![];
    wallet.write(&mut bytes).await.unwrap();
    std::fs::write(out("zwl-testnet-empty.dat"), bytes).unwrap();
    wallet.txns().write().await.add_taddr_spent(TxId::from_bytes([7; 32]), BlockHeight::from(1), false, 1_700_000_000, 0);
    let mut bytes = vec![];
    wallet.write(&mut bytes).await.unwrap();
    std::fs::write(out("zwl-testnet-txn.dat"), bytes).unwrap();
}
RS
RUSTUP_TOOLCHAIN=1.72.1 RUSTC_WRAPPER= CARGO_TARGET_DIR="$WORK/target" cargo run -p zecwalletlitelib --example generate_empty
shasum -a 256 "$ARGOS_FIXTURES"/zwl-*.dat
```

The generator writes into `$ARGOS_FIXTURES`. The output is the writer's full wallet serialization with empty block histories. The third fixture contains one zero-value transaction metadata record written through `WalletTxns::add_taddr_spent`, not a hand-assembled parser vector. `LightWallet::new` creates deterministic initial addresses from the published seed; no chain data or private user material is included.

SHA-256:

- `zwl-mainnet-empty.dat`: `c99bc4efb96f1b7e1797678e0dd3b4b9f780977d1833e64d04d08e47f2faa735`
- `zwl-testnet-empty.dat`: `d9223d923a79833cb504f798f5d4ec32a52fbaf0778ee9200c25bce2d53eacab`
- `zwl-testnet-txn.dat`: `f33055ba75d591391c591ddb7c9c0b9045b29d5ce78dd73d66388e261cd80650`
