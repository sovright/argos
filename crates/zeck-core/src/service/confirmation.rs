//! Submitting a signed batch and waiting for confirmation evidence.

use super::*;

pub(super) async fn broadcast_transactions(
    ctx: &mut SweepStepCtx<'_>,
    wallet_db: &mut WalletDb<
        rusqlite::Connection,
        crate::workspace::ArgosParams,
        SystemClock,
        rand_core::OsRng,
    >,
    account_index: u32,
    txids: Vec<TxId>,
    label: &str,
    reviewed_batch_fee_zatoshis: u64,
) -> ZeckResult<()> {
    use rusqlite::OptionalExtension;

    let log = &mut *ctx.broadcast_log;

    // An earlier leg of this execution that was accepted (Pending) does not
    // stop this one: it spends disjoint reviewed inputs.
    if let Some(txid) = log.blocking_next_leg() {
        return Err(ZeckError::Broadcast(format!(
            "transaction {txid} may already have reached the network or was retryably refused; reconcile its durable record before another submission"
        )));
    }
    let fee_db = rusqlite::Connection::open_with_flags(
        ctx.workspace.wallet_db_path(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|err| ZeckError::Wallet(format!("opening wallet fee records: {err}")))?;
    let mut prepared = Vec::with_capacity(txids.len());
    for txid in txids {
        let tx = wallet_db
            .get_transaction(txid)
            .map_err(|err| ZeckError::Wallet(format!("loading {label} transaction {txid}: {err}")))?
            .ok_or_else(|| {
                ZeckError::Wallet(format!(
                    "wallet did not persist the {label} transaction {txid}"
                ))
            })?;

        let mut tx_bytes = Vec::new();
        tx.write(&mut tx_bytes).map_err(|err| {
            ZeckError::TransactionBuild(format!("serializing transaction {txid}: {err}"))
        })?;
        let fee_zatoshis: Option<i64> = fee_db
            .query_row(
                "SELECT fee FROM transactions WHERE txid = ?1",
                [txid.as_ref()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| ZeckError::Wallet(format!("reading transaction fee for {txid}: {err}")))?
            .flatten();
        let fee_zatoshis = fee_zatoshis
            .and_then(|fee| u64::try_from(fee).ok())
            .ok_or_else(|| {
                ZeckError::Wallet(format!(
                    "wallet did not persist a valid fee for {label} transaction {txid}"
                ))
            })?;
        prepared.push(PreparedTransaction {
            txid,
            raw_tx: tx_bytes,
            fee_zatoshis,
            expiry_height: Some(u32::from(tx.expiry_height())),
        });
    }
    // The reviewed fee was already compared with the proposal before it was
    // built and stored. This second check reads the fee the wallet recorded
    // for the built transaction. On a mismatch nothing is submitted or
    // journaled; the wallet's unsent transaction keeps its inputs reserved
    // only until its expiry height, after which a rescan frees them.
    if let Err(err) = require_persisted_batch_fee(
        reviewed_batch_fee_zatoshis,
        prepared.iter().map(|tx| tx.fee_zatoshis),
    ) {
        tracing::warn!(
            "{label} batch not submitted: {err}; inputs are released at expiry height(s) {:?}",
            prepared
                .iter()
                .map(|tx| tx.expiry_height)
                .collect::<Vec<_>>()
        );
        return Err(err);
    }
    enforce_max_fee(
        checked_fee_total(ctx.prior_fee_zatoshis, reviewed_batch_fee_zatoshis)?,
        ctx.max_fee_zatoshis,
    )?;
    let mut observer = LightwalletdTxObserver::new(ctx.lightwalletd_url, ctx.confirmation_sources)?;
    submit_and_confirm_batch(
        prepared,
        account_index,
        label,
        ctx.results,
        log,
        &mut LightwalletdSubmitter { client: ctx.client },
        &mut observer,
        ctx.network,
        &mut |txid, height| {
            wallet_db
                .set_transaction_status(
                    txid,
                    TransactionStatus::Mined(BlockHeight::from_u32(height)),
                )
                .map_err(|err| {
                    ZeckError::Wallet(format!(
                        "marking mined transaction {txid} in wallet db: {err}"
                    ))
                })
        },
    )
    .await
}

/// Submit one leg's prepared transactions and poll each for confirmation.
/// Separated from wallet access so the leg-to-leg gating is testable
/// against a scripted node and observer.
///
/// Gating within one reviewed execution: an earlier leg that was accepted
/// (Pending) does not stop this one, since every leg spends disjoint
/// reviewed inputs. Only an unknown outcome (lost reply, retryable refusal)
/// blocks the next submission.
#[allow(clippy::too_many_arguments)]
pub(super) async fn submit_and_confirm_batch<N, O>(
    prepared: Vec<PreparedTransaction>,
    account_index: u32,
    label: &str,
    results: &mut Vec<TxBroadcastResult>,
    log: &mut DurableBroadcastLog,
    submitter: &mut N,
    observer: &mut O,
    network: crate::models::ZeckNetwork,
    mark_mined: &mut (dyn FnMut(TxId, u32) -> ZeckResult<()> + Send),
) -> ZeckResult<()>
where
    N: crate::broadcast::TxSubmitter,
    O: TxObserver,
{
    if let Some(txid) = log.blocking_next_leg() {
        return Err(ZeckError::Broadcast(format!(
            "transaction {txid} may already have reached the network or was retryably refused; reconcile its durable record before another submission"
        )));
    }
    for tx in prepared {
        let txid = tx.txid;
        let fee_zatoshis = tx.fee_zatoshis;
        let expiry_height = tx.expiry_height;
        let submission =
            submit_prepared_transaction(log, submitter, tx, Duration::from_secs(30)).await?;

        // Record the submission before examining its disposition. A lost reply
        // still leaves a known txid, fee, and possibly an on-chain transaction.
        // Accepted submissions are updated if confirmation polling resolves.
        let result_index = results.len();
        results.push(TxBroadcastResult {
            source_account: account_index,
            txid: Some(txid.to_string()),
            status: submission.state,
            fee_zatoshis,
            detail: format!(
                "{label} submission: {:?}{}",
                submission.disposition,
                submission
                    .persistence_warning
                    .as_ref()
                    .map(|warning| format!(" Persistence warning: {warning}"))
                    .unwrap_or_default()
            ),
            confirmed_height: None,
            safe_to_discard: false,
        });
        if submission.blocks_followup_submission() {
            return Err(ZeckError::Broadcast(format!(
                "{label} transaction {txid} may already have reached the network or was retryably refused; reconcile its stored bytes before retrying or submitting another sweep leg",
            )));
        }
        if submission.state == TxLifecycleState::Rejected {
            return Err(ZeckError::Broadcast(format!(
                "{label} transaction {txid} was rejected: {:?}",
                submission.disposition,
            )));
        }

        let confirmation = wait_for_confirmation(
            mark_mined,
            log,
            observer,
            network,
            txid,
            expiry_height,
            label,
        )
        .await?;
        let entry = &mut results[result_index];
        entry.status = confirmation.state;
        entry.detail = confirmation.detail;
        entry.confirmed_height = confirmation.confirmed_height;
        entry.safe_to_discard = confirmation.safe_to_discard;
    }

    Ok(())
}

#[cfg(test)]
pub(super) fn is_distinct_lightwalletd_endpoint(candidate: &str, primary: &str) -> bool {
    crate::lightwalletd::normalized_endpoint_authority(candidate).ok()
        != crate::lightwalletd::normalized_endpoint_authority(primary).ok()
}

/// Poll a submitted transaction until it mines (by any configured operator),
/// expires, or the polling budget runs out. Returns the lifecycle state, a
/// detail line, the mined height, and whether it is safe to discard the source.
pub(super) async fn wait_for_confirmation<O: TxObserver>(
    mark_mined: &mut (dyn FnMut(TxId, u32) -> ZeckResult<()> + Send),
    log: &mut impl BroadcastStore,
    observer: &mut O,
    network: crate::models::ZeckNetwork,
    txid: TxId,
    expiry_height: Option<u32>,
    label: &str,
) -> ZeckResult<ConfirmationResult> {
    let mut last_state = TxObservationState::Unavailable;
    for attempt in 0..CONFIRMATION_POLL_ATTEMPTS {
        let observation = observer.observe(network, txid, expiry_height).await?;
        last_state = observation.state.clone();
        let state = crate::reconciliation::record_observation(log, txid, &observation)?;
        if state.is_mined() {
            let evidence = if observation.state_is_mined() {
                observation
            } else {
                log.latest(txid)
                    .and_then(|record| record.observation)
                    .ok_or_else(|| {
                        ZeckError::Broadcast(format!("mined record {txid} has no evidence"))
                    })?
            };
            let height = evidence.mined_height.ok_or_else(|| {
                ZeckError::Broadcast(format!("mining evidence for {txid} has no height"))
            })?;
            mark_mined(txid, height)?;
            let safe_to_discard = state == TxLifecycleState::Mined && evidence.is_safe_to_discard();
            return Ok(ConfirmationResult {
                state,
                detail: format!(
                    "{label}: {}",
                    crate::reconciliation::lifecycle_detail(
                        state,
                        &evidence.state,
                        Some(height),
                        safe_to_discard
                    )
                ),
                confirmed_height: Some(height),
                safe_to_discard,
            });
        }
        if state == TxLifecycleState::Expired {
            return Ok(ConfirmationResult {
                state,
                detail: format!(
                    "{label} transaction expired: reported absent from chain and mempool past its expiry height."
                ),
                confirmed_height: None,
                safe_to_discard: false,
            });
        }
        if attempt + 1 < CONFIRMATION_POLL_ATTEMPTS {
            tokio::time::sleep(Duration::from_secs(CONFIRMATION_POLL_INTERVAL_SECS)).await;
        }
    }
    let state = log
        .latest(txid)
        .ok_or_else(|| ZeckError::Storage(format!("missing prepared transaction {txid}")))?
        .state;
    let detail = if state == TxLifecycleState::SubmissionUnknown {
        format!(
            "{label} submission remains unknown ({last_state:?}); reconcile its stored bytes before another sweep leg."
        )
    } else {
        format!(
            "{label} transaction is pending ({last_state:?}); mining evidence is not yet available."
        )
    };
    Ok(ConfirmationResult {
        state,
        detail,
        confirmed_height: None,
        safe_to_discard: false,
    })
}

pub(super) struct ConfirmationResult {
    pub(super) state: TxLifecycleState,
    pub(super) detail: String,
    pub(super) confirmed_height: Option<u32>,
    pub(super) safe_to_discard: bool,
}

pub(super) async fn chain_tip_height(
    client: &mut CompactTxStreamerClient<tonic::transport::Channel>,
) -> ZeckResult<u32> {
    let info = client
        .get_lightd_info(zcash_client_backend::proto::service::Empty {})
        .await
        .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
        .into_inner();
    u32::try_from(info.block_height)
        .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))
}
