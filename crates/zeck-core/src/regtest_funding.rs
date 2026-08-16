//! Transfer-based funding for the regtest harness.
//!
//! ## Why this exists
//!
//! The harness funds test addresses with shielded coinbase, which only works
//! near genesis. Regtest halves the block subsidy every ~150 blocks, so it is
//! worth nothing past about height 6,000 — while ZIP 212 enforcement, which
//! PCZT construction requires, does not begin until 32,257. The two windows do
//! not overlap.
//!
//! The consequence was that every funded address was funded once, near
//! genesis, and could never be refilled. A sweep test drains its address, so
//! the suite could not be run twice against the same chain: the second run
//! reported failures that looked like defects but were empty wallets. That is
//! cause 6 of #186, and it is why `tests/regtest/README.md` could tell
//! contributors to run the suite before merging without that being achievable.
//!
//! Zebra cannot fix this from config. `pre_blossom_halving_interval` exists
//! and is accepted on Regtest, but `Parameters::new_regtest` hardcodes the
//! interval and ignores it — see the comment in `zebrad-regtest.toml`.
//!
//! So funding moves off coinbase. A *treasury* seed is paid a large shielded
//! coinbase balance near genesis, once, while the subsidy is still worth
//! something. Afterwards any address can be funded at any height by spending
//! from the treasury, because an ordinary shielded transfer does not care what
//! the block subsidy is doing.
//!
//! ## Why it lives in the library rather than the funder binary
//!
//! It needs `open_wallet_db` and the workspace layout, both `pub(crate)`.
//! Gated behind `argos-network` for the same reason `set_regtest_consensus_params`
//! is: a released binary must contain no code that spends from a hardcoded
//! seed.

use std::{collections::HashMap, convert::Infallible, path::PathBuf, sync::Arc};

use secrecy::{ExposeSecret, SecretString};
use zcash_address::ZcashAddress;
use zcash_client_backend::{
    data_api::{
        wallet::{
            create_proposed_transactions,
            input_selection::{GreedyInputSelector, SpendPolicy},
            propose_transfer, ConfirmationsPolicy, SpendingKeys,
        },
        WalletRead,
    },
    fees::{standard::SingleOutputChangeStrategy, DustOutputPolicy, StandardFeeRule},
    proto::service::RawTransaction,
    wallet::OvkPolicy,
};
#[allow(deprecated)]
use zcash_client_backend::zip321;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_proofs::prover::LocalTxProver;
use zcash_protocol::{value::Zatoshis, ShieldedPool};

use crate::{
    error::{ZeckError, ZeckResult},
    key_source::SeedKeySource,
    models::{RuntimeScanConfig, ZeckNetwork},
    workspace::{consensus_network, open_wallet_db, RecoveryWorkspace},
    RecoveryService, ScanConfig, ScanPhase,
};

/// Outcome of a treasury transfer.
pub struct TreasuryTransfer {
    pub txid: String,
    /// The treasury's balance after the transfer, so a caller can warn before
    /// it runs dry rather than after.
    pub remaining_zatoshis: u64,
}

/// Pay `amount_zatoshis` from the treasury seed to `destination`.
///
/// Scans the treasury first: the notes it spends were mined long before this
/// call, so the wallet has to catch up before it can select them.
///
/// `data_dir` is reused deliberately rather than being a fresh temp directory.
/// The workspace persists between invocations and the scan resumes from
/// `fully_scanned_height`, so the first funding call on a chain pays the full
/// scan cost and subsequent ones are cheap. A fresh directory each time would
/// make every top-up rescan the whole chain.
///
/// The cost of that persistence: the workspace outlives the chain. It sits
/// outside the docker volumes, so `docker compose down -v` wipes the chain and
/// leaves the wallet believing it is synced past the new chain's tip. The next
/// scan then asks for a block that does not exist yet and fails with
/// "block N is newer than the latest block", which looks like a lightwalletd
/// fault. `setup.sh` removes the directory when it rebuilds; a caller passing
/// its own `data_dir` across chains has to do the same.
pub async fn transfer_from_treasury(
    treasury_seed: &SecretString,
    payments: &[(String, u64)],
    lightwalletd_url: &str,
    data_dir: PathBuf,
    network: ZeckNetwork,
) -> ZeckResult<TreasuryTransfer> {
    if payments.is_empty() {
        return Err(ZeckError::InvalidConfig(
            "a treasury transfer needs at least one payment".to_owned(),
        ));
    }
    let config = ScanConfig {
        birthday: 1,
        num_accounts: Some(1),
        gap_limit: 1,
        lightwalletd_url: lightwalletd_url.to_owned(),
        data_dir: data_dir.clone(),
        network,
        label: "regtest-treasury".to_owned(),
    };

    // Phase timings on stderr. Funding dominated the regtest suite -- two
    // tests calling this were 97% of a 5-hour run -- and the only way to tell
    // a slow scan from slow proving is to measure both.
    let started = std::time::Instant::now();
    macro_rules! phase {
        ($name:expr) => {
            eprintln!("[funder] {} at {:.1}s", $name, started.elapsed().as_secs_f64())
        };
    }

    // Scan through the ordinary service so account import, workspace keying
    // and sync stay in one place rather than being reimplemented here.
    phase!("scan: start");
    let service = RecoveryService::new();
    let handle = service
        .start_scan(config.clone(), treasury_seed.clone())
        .await?;
    let mut last_phase: Option<ScanPhase> = None;
    loop {
        let progress = service.get_scan_progress(&handle).await?;
        // Which phase the time goes to. A fully-scanned workspace still spent
        // 1h44m here with two blocks pending, so the cost is not block
        // fetching and the phase boundary is the only way to see where it is.
        if last_phase != Some(progress.phase) {
            eprintln!(
                "[funder] phase {:?} at {:.1}s (synced_to {:?}, blocks {})",
                progress.phase,
                started.elapsed().as_secs_f64(),
                progress.synced_to_height,
                progress.blocks_scanned,
            );
            last_phase = Some(progress.phase);
        }
        match progress.phase {
            ScanPhase::Complete => break,
            ScanPhase::Error => {
                return Err(ZeckError::Wallet(format!(
                    "treasury scan failed: {:?}",
                    progress.error
                )))
            }
            ScanPhase::Cancelled => {
                return Err(ZeckError::Wallet("treasury scan was cancelled".to_owned()))
            }
            _ => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
    }

    phase!("scan: complete");

    let runtime = RuntimeScanConfig {
        key_source: Arc::new(SeedKeySource::new(treasury_seed.clone())),
        birthday: config.birthday,
        num_accounts: config.num_accounts,
        gap_limit: config.gap_limit,
        lightwalletd_url: config.lightwalletd_url.clone(),
        data_dir: config.data_dir.clone(),
        network,
        label: config.label.clone(),
    };
    let workspace = RecoveryWorkspace::from_runtime(&runtime)?;
    let params = consensus_network(network);
    let mut wallet_db = open_wallet_db(workspace.wallet_db_path(), params)?;

    let account_id = wallet_db
        .get_account_ids()
        .map_err(|err| ZeckError::Wallet(format!("listing treasury accounts: {err}")))?
        .into_iter()
        .next()
        .ok_or_else(|| ZeckError::Wallet("the treasury workspace has no account".to_owned()))?;

    let seed_bytes = crate::derivation::mnemonic_seed(treasury_seed)?;
    let usk = UnifiedSpendingKey::from_seed(
        &params,
        seed_bytes.expose_secret(),
        zip32::AccountId::ZERO,
    )
        .map_err(|err| ZeckError::Wallet(format!("deriving the treasury key: {err}")))?;

    // All destinations in one transaction. Funding them one at a time would
    // need a mined block and a rescan between each, so that the next call can
    // see the previous one's change note — minutes per destination against a
    // 32,000-block chain.
    let mut zip321_payments = Vec::with_capacity(payments.len());
    for (destination, amount_zatoshis) in payments {
        let recipient = ZcashAddress::try_from_encoded(destination).map_err(|err| {
            ZeckError::InvalidConfig(format!("bad funding destination {destination}: {err}"))
        })?;
        zip321_payments.push(
            zip321::Payment::new(
                recipient,
                Some(Zatoshis::from_u64(*amount_zatoshis).map_err(|err| {
                    ZeckError::InvalidConfig(format!("bad amount for {destination}: {err}"))
                })?),
                None,
                None,
                None,
                vec![],
            )
            .map_err(|err| {
                ZeckError::InvalidConfig(format!("invalid payment to {destination}: {err}"))
            })?,
        );
    }
    let request = zip321::TransactionRequest::new(zip321_payments)
        .map_err(|err| ZeckError::TransactionBuild(format!("building funding request: {err}")))?;

    let input_selector = GreedyInputSelector::<_>::new();
    let change_strategy = SingleOutputChangeStrategy::new(
        StandardFeeRule::Zip317,
        None,
        ShieldedPool::Sapling,
        DustOutputPolicy::default(),
    );

    let proposal = propose_transfer::<_, _, _, _, Infallible>(
        &mut wallet_db,
        &params,
        account_id,
        &input_selector,
        &change_strategy,
        request,
        ConfirmationsPolicy::MIN,
        // Shielded only. The treasury's coinbase is shielded (ZIP 213), and a
        // transaction spending transparent coinbase may not have transparent
        // outputs — which a funding payment to a t-address would be.
        &SpendPolicy::shielded_pools([ShieldedPool::Sapling, ShieldedPool::Orchard]),
        None,
        None,
    )
    .map_err(|err| ZeckError::TransactionBuild(format!("proposing the funding transfer: {err}")))?;

    phase!("proposal: built");
    let prover = LocalTxProver::bundled();
    phase!("prover: loaded");
    let txids = create_proposed_transactions::<_, _, Infallible, _, Infallible, _>(
        &mut wallet_db,
        &params,
        &prover,
        &prover,
        &SpendingKeys::new(usk, HashMap::new()),
        OvkPolicy::Sender,
        &proposal,
        None,
    )
    .map_err(|err| {
        ZeckError::TransactionBuild(format!("creating the funding transaction: {err}"))
    })?;

    let txid = *txids.first();

    phase!("transaction: built");
    let (mut client, _endpoint) =
        crate::lightwalletd::connect_lightwalletd_endpoints(lightwalletd_url, None).await?;
    let tx = wallet_db
        .get_transaction(txid)
        .map_err(|err| ZeckError::Wallet(format!("loading the funding transaction: {err}")))?
        .ok_or_else(|| ZeckError::Wallet("the funding transaction vanished".to_owned()))?;
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|err| ZeckError::TransactionBuild(format!("serializing: {err}")))?;

    let response = client
        .send_transaction(RawTransaction {
            data: raw,
            height: 0,
        })
        .await
        .map_err(|err| ZeckError::Broadcast(err.to_string()))?
        .into_inner();
    if response.error_code != 0 {
        return Err(ZeckError::Broadcast(format!(
            "the node rejected the funding transaction: {}",
            response.error_message
        )));
    }

    phase!("broadcast: done");

    let remaining = wallet_db
        .get_wallet_summary(ConfirmationsPolicy::MIN)
        .map_err(|err| ZeckError::Wallet(format!("reading treasury balance: {err}")))?
        .map(|summary| {
            summary
                .account_balances()
                .values()
                .map(|b| u64::from(b.total()))
                .sum::<u64>()
        })
        .unwrap_or(0);

    Ok(TreasuryTransfer {
        txid: txid.to_string(),
        remaining_zatoshis: remaining,
    })
}
