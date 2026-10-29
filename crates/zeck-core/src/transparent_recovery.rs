//! Recovery for wallets whose keys are transparent-only.
//!
//! A zcashd wallet that never held a shielded address cannot be given a
//! wallet-database account at all: ZIP-316 forbids a unified container of
//! only transparent items, so there is no UFVK to anchor one to
//! (zcash/librustzcash#2582).
//!
//! That limit is narrower than it first appears. The account model exists
//! to serve *shielded* scanning — trial decryption, witnesses, the note
//! commitment tree. Transparent funds need none of it: lightwalletd's
//! `GetAddressUtxos` answers "what can this address spend" directly, and
//! the transaction builder accepts transparent inputs by outpoint and key.
//! So this module deliberately bypasses `zcash_client_sqlite` entirely
//! rather than trying to satisfy an abstraction it does not need.
//!
//! Scope: it reports **current spendable UTXOs**, not history. A wallet
//! that was funded and later emptied reports zero here, which is the right
//! answer to "what can I recover" and the wrong answer to "what did this
//! wallet ever hold". Callers must not present it as the latter.
//!
//! Standalone callers must present a quote before submitting. The old direct
//! signer is deliberately absent from the public API:
//!
//! ```compile_fail
//! use argos_core::transparent_recovery::sweep_transparent_only;
//! ```
//!
//! There is no standalone per-key journal opener; the network registry
//! guard owns journal opening:
//!
//! ```compile_fail
//! use argos_core::transparent_recovery::open_standalone_broadcast_log;
//! ```

use sapling_crypto as sapling;
use tonic::transport::Channel;
use tracing::warn;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, GetAddressUtxosArg, GetAddressUtxosReply,
};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};

use crate::{
    broadcast::{
        submit_prepared_transaction, BroadcastStore, LightwalletdSubmitter, PreparedTransaction,
        TxSubmitter,
    },
    error::{ZeckError, ZeckResult},
    imported::{encode_transparent_address, ImportedTransparentKey},
    models::{TxBroadcastResult, ZeckNetwork},
};

/// lightwalletd is queried in batches so a wallet with many addresses does
/// not build one enormous request. zcashd wallets routinely hold hundreds
/// of transparent keys (the golden fixture has 103).
const ADDRESS_BATCH: usize = 50;

/// A spendable transparent output, with everything the builder needs to
/// spend it and everything the user needs to understand it.
#[derive(Debug, Clone)]
pub struct TransparentUtxo {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub address: TransparentAddress,
    pub height: u64,
}

/// Per-address balance, for display.
#[derive(Debug, Clone)]
pub struct TransparentAddressBalance {
    pub address: String,
    pub zatoshis: u64,
    pub utxo_count: u32,
}

/// What a transparent-only scan found.
#[derive(Debug, Clone)]
pub struct TransparentScanReport {
    /// Only addresses holding funds, most valuable first. An address with
    /// nothing in it is noise in a 103-address wallet.
    pub funded: Vec<TransparentAddressBalance>,
    pub total_zatoshis: u64,
    pub addresses_checked: usize,
    pub chain_tip_height: u32,
}

/// Fetch every spendable UTXO controlled by `keys`.
///
/// Addresses with no UTXOs simply do not appear in the reply; that is not
/// an error.
pub async fn fetch_transparent_utxos(
    client: &mut CompactTxStreamerClient<Channel>,
    keys: &[ImportedTransparentKey],
    network: ZeckNetwork,
) -> ZeckResult<Vec<TransparentUtxo>> {
    // Map encoded address back to the parsed form, so a reply can be tied
    // to the key that spends it without re-parsing.
    let mut by_encoded = std::collections::HashMap::with_capacity(keys.len());
    for key in keys {
        by_encoded.insert(
            encode_transparent_address(&key.address, network),
            key.address,
        );
    }

    let encoded: Vec<String> = by_encoded.keys().cloned().collect();
    let mut utxos = Vec::new();

    for batch in encoded.chunks(ADDRESS_BATCH) {
        let reply = client
            .get_address_utxos(GetAddressUtxosArg {
                addresses: batch.to_vec(),
                start_height: 0,
                max_entries: 0,
            })
            .await
            .map_err(|err| ZeckError::Lightwalletd(err.to_string()))?
            .into_inner();

        for entry in reply.address_utxos {
            let Some(&address) = by_encoded.get(&entry.address) else {
                // lightwalletd answered for an address we did not ask
                // about. Not fatal, but it is the server misbehaving and
                // must not silently become part of a balance.
                warn!(
                    "lightwalletd returned a UTXO for unrequested address {}; ignoring",
                    entry.address
                );
                continue;
            };

            if let Some(utxo) = parse_reported_utxo(entry, address)? {
                utxos.push(utxo);
            }
        }
    }

    deduplicate_fetched_utxos(utxos)
}

/// Validate a server-reported coin against the address we control. A
/// nonempty script is part of the server's outpoint claim, so a mismatch is
/// an integrity failure even if another reply for that outpoint is valid.
fn parse_reported_utxo(
    entry: GetAddressUtxosReply,
    address: TransparentAddress,
) -> ZeckResult<Option<TransparentUtxo>> {
    let value = match u64::try_from(entry.value_zat)
        .ok()
        .and_then(|v| Zatoshis::from_u64(v).ok())
    {
        Some(v) => v,
        None => {
            warn!(
                "lightwalletd returned out-of-range value_zat={} for {}; skipping",
                entry.value_zat, entry.address
            );
            return Ok(None);
        }
    };
    let txid: [u8; 32] = match entry.txid.as_slice().try_into() {
        Ok(txid) => txid,
        Err(_) => {
            warn!(
                "lightwalletd returned a {}-byte txid for {}; skipping",
                entry.txid.len(),
                entry.address
            );
            return Ok(None);
        }
    };
    let index = match u32::try_from(entry.index) {
        Ok(index) => index,
        Err(_) => {
            warn!(
                "lightwalletd returned a negative output index for {}; skipping",
                entry.address
            );
            return Ok(None);
        }
    };

    let expected_script: zcash_transparent::address::Script = address.script().into();
    if !entry.script.is_empty() && entry.script != expected_script.0 .0 {
        return Err(ZeckError::Wallet(format!(
            "lightwalletd reported a conflicting script for transparent outpoint {:?}",
            OutPoint::new(txid, index)
        )));
    }
    Ok(Some(TransparentUtxo {
        outpoint: OutPoint::new(txid, index),
        txout: TxOut::new(value, expected_script),
        address,
        height: entry.height,
    }))
}

/// Treat an outpoint as one coin even when a server repeats it in a batch.
/// Conflicting replies cannot establish a trustworthy amount or owner.
fn deduplicate_fetched_utxos(utxos: Vec<TransparentUtxo>) -> ZeckResult<Vec<TransparentUtxo>> {
    let mut by_outpoint = std::collections::HashMap::<OutPoint, usize>::new();
    let mut unique: Vec<TransparentUtxo> = Vec::with_capacity(utxos.len());
    for utxo in utxos {
        if let Some(&previous_index) = by_outpoint.get(&utxo.outpoint) {
            let previous = &unique[previous_index];
            if previous.address != utxo.address || previous.txout != utxo.txout {
                return Err(ZeckError::Wallet(format!(
                    "conflicting lightwalletd records for transparent outpoint {:?}",
                    utxo.outpoint
                )));
            }
            continue;
        }
        by_outpoint.insert(utxo.outpoint.clone(), unique.len());
        unique.push(utxo);
    }
    Ok(unique)
}

/// Summarize a UTXO set into a per-address report.
pub fn summarize(
    utxos: &[TransparentUtxo],
    addresses_checked: usize,
    chain_tip_height: u32,
    network: ZeckNetwork,
) -> TransparentScanReport {
    let mut sums: std::collections::HashMap<TransparentAddress, (u64, u32)> =
        std::collections::HashMap::new();
    let mut total = 0u64;
    let mut seen_outpoints = std::collections::HashSet::new();

    for utxo in utxos {
        if !seen_outpoints.insert(&utxo.outpoint) {
            continue;
        }
        let value = u64::from(utxo.txout.value());
        let entry = sums.entry(utxo.address).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(value);
        entry.1 = entry.1.saturating_add(1);
        total = total.saturating_add(value);
    }

    let mut funded: Vec<TransparentAddressBalance> = sums
        .into_iter()
        .map(
            |(address, (zatoshis, utxo_count))| TransparentAddressBalance {
                address: encode_transparent_address(&address, network),
                zatoshis,
                utxo_count,
            },
        )
        .collect();
    // Deterministic order: value first so the user sees what matters, then
    // address so the output is stable across runs for the same wallet.
    funded.sort_by(|a, b| {
        b.zatoshis
            .cmp(&a.zatoshis)
            .then_with(|| a.address.cmp(&b.address))
    });

    TransparentScanReport {
        funded,
        total_zatoshis: total,
        addresses_checked,
        chain_tip_height,
    }
}

/// A costed transparent sweep, before anything is signed or broadcast.
///
/// Produced separately from execution so a dry run and a real sweep agree
/// by construction rather than by two code paths happening to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentSweepPlan {
    pub input_count: usize,
    pub total_input_zatoshis: u64,
    pub fee_zatoshis: u64,
    /// What actually lands at the destination: inputs minus fee.
    pub output_zatoshis: u64,
}

/// A transparent-only sweep review bound to its complete spendable input set.
///
/// The inputs and target height stay private so a caller cannot replace the
/// coins after displaying the fee. Execution refreshes the live set before
/// signing and consumes that validated set without fetching it again.
#[derive(Debug)]
pub struct TransparentSweepQuote {
    report: TransparentScanReport,
    plan: Option<TransparentSweepPlan>,
    utxos: Vec<TransparentUtxo>,
    target_height: u32,
    key_addresses: Vec<String>,
    network: ZeckNetwork,
}

impl TransparentSweepQuote {
    pub fn report(&self) -> &TransparentScanReport {
        &self.report
    }

    pub fn plan(&self) -> Option<&TransparentSweepPlan> {
        self.plan.as_ref()
    }
}

fn transparent_key_addresses(keys: &[ImportedTransparentKey], network: ZeckNetwork) -> Vec<String> {
    let mut addresses = keys
        .iter()
        .map(|key| encode_transparent_address(&key.address, network))
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    addresses
}

/// A stable byte identity for a transparent address: a kind tag (0 for
/// P2PKH, 1 for P2SH) followed by the 20-byte hash. Unlike `Debug` text it
/// cannot change with an upstream formatting change.
pub(crate) fn transparent_address_identity(address: &TransparentAddress) -> [u8; 21] {
    let (tag, hash) = match address {
        TransparentAddress::PublicKeyHash(hash) => (0, hash),
        TransparentAddress::ScriptHash(hash) => (1, hash),
    };
    let mut bytes = [0u8; 21];
    bytes[0] = tag;
    bytes[1..].copy_from_slice(hash);
    bytes
}

fn transparent_input_identity(utxo: &TransparentUtxo) -> Vec<u8> {
    let mut bytes = utxo.outpoint.hash().to_vec();
    bytes.extend_from_slice(&utxo.outpoint.n().to_le_bytes());
    utxo.txout
        .write(&mut bytes)
        .expect("serializing a TxOut into Vec cannot fail");
    bytes.extend_from_slice(&transparent_address_identity(&utxo.address));
    bytes.extend_from_slice(&utxo.height.to_le_bytes());
    bytes
}

fn transparent_input_set_identity(utxos: &[TransparentUtxo]) -> Vec<Vec<u8>> {
    let mut inputs = utxos
        .iter()
        .map(transparent_input_identity)
        .collect::<Vec<_>>();
    inputs.sort();
    inputs
}

/// Fetch and cost the exact transparent inputs a standalone CLI sweep will
/// show before confirmation. No signing or submission takes place.
pub async fn quote_transparent_only(
    keys: &[ImportedTransparentKey],
    network: ZeckNetwork,
    lightwalletd_url: &str,
) -> ZeckResult<TransparentSweepQuote> {
    use zcash_protocol::consensus::BlockHeight;

    let (mut client, _endpoint, info) =
        crate::lightwalletd::probe_lightwalletd_endpoints_with_retry(lightwalletd_url).await?;
    crate::lightwalletd::validate_lightwalletd_network(network, &info)?;
    let chain_tip = u32::try_from(info.block_height)
        .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))?;
    let target_height = chain_tip.saturating_add(1);
    let utxos = fetch_transparent_utxos(&mut client, keys, network).await?;
    let report = summarize(&utxos, keys.len(), chain_tip, network);
    let plan = plan_sweep(
        &crate::workspace::consensus_network(network),
        BlockHeight::from_u32(target_height),
        &utxos,
    )?;
    Ok(TransparentSweepQuote {
        report,
        plan,
        utxos,
        target_height,
        key_addresses: transparent_key_addresses(keys, network),
        network,
    })
}

/// The ZIP-317 fee for sweeping `input_count` P2PKH inputs into a single
/// Sapling output — the transaction `sweep_transparent_only` builds.
///
/// One function for the plan and the preview, so the fee a user is shown
/// before the scan finishes is the fee the builder charges.
fn zip317_sweep_fee<P: zcash_protocol::consensus::Parameters>(
    params: &P,
    target_height: zcash_protocol::consensus::BlockHeight,
    input_count: usize,
) -> ZeckResult<u64> {
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};

    let input_sizes = std::iter::repeat_n(
        zcash_primitives::transaction::fees::transparent::InputSize::STANDARD_P2PKH,
        input_count,
    )
    .collect::<Vec<_>>();

    // A Sapling bundle pads its outputs to `MIN_SHIELDED_OUTPUTS` for
    // privacy, so the single output we add is billed as more than one. Ask
    // the bundle type rather than assuming: this is the same call the
    // builder's own `get_fee` makes, so the two cannot drift. Getting it
    // wrong underpays the fee and the node rejects the transaction after
    // the user has been told what it would cost.
    let sapling_outputs = sapling::builder::BundleType::DEFAULT
        .num_outputs(0, 1)
        .map_err(|err| ZeckError::Internal(format!("sizing the Sapling bundle: {err}")))?;

    let fee = FeeRule::standard()
        .fee_required(
            params,
            target_height,
            input_sizes,
            // No transparent outputs: the single output is shielded.
            std::iter::empty(),
            0,
            sapling_outputs,
            0,
            0,
        )
        .map_err(|err| ZeckError::Wallet(format!("computing the ZIP-317 fee failed: {err:?}")))?;
    Ok(u64::from(fee))
}

/// [`zip317_sweep_fee`] for a preview, which has a network but no chain tip.
/// ZIP-317's standard rule does not vary by height past NU5, so NU5
/// activation stands in for it.
pub fn transparent_sweep_fee(network: ZeckNetwork, input_count: usize) -> ZeckResult<u64> {
    use zcash_protocol::consensus::{NetworkUpgrade, Parameters as _};
    let params = crate::workspace::consensus_network(network);
    let height = params
        .activation_height(NetworkUpgrade::Nu5)
        .ok_or_else(|| {
            ZeckError::Internal("NU5 has no activation height on this network".to_owned())
        })?;
    zip317_sweep_fee(&params, height, input_count)
}

/// Cost a sweep of every supplied UTXO into a single shielded output.
///
/// Sweeping *everything* into *one* output is what makes this costable in
/// advance: there is no change, so the fee depends only on the input count.
///
/// Returns `None` when the wallet holds nothing. Returns an error when the
/// balance cannot cover its own fee — the honest answer for dust, rather
/// than building a transaction the network will reject.
pub fn plan_sweep<P: zcash_protocol::consensus::Parameters>(
    params: &P,
    target_height: zcash_protocol::consensus::BlockHeight,
    utxos: &[TransparentUtxo],
) -> ZeckResult<Option<TransparentSweepPlan>> {
    if utxos.is_empty() {
        return Ok(None);
    }

    // The builder consumes the exact slice being priced. Even an identical
    // duplicate would create two inputs for one coin; reject before proving.
    let mut seen_outpoints = std::collections::HashSet::new();
    for utxo in utxos {
        if !seen_outpoints.insert(&utxo.outpoint) {
            return Err(ZeckError::Wallet(format!(
                "duplicate transparent outpoint {:?} in sweep inputs",
                utxo.outpoint
            )));
        }
    }

    let total: u64 = utxos.iter().fold(0u64, |acc, u| {
        acc.saturating_add(u64::from(u.txout.value()))
    });

    // Every input is P2PKH — these keys came from `key`/`ckey` records,
    // which store pubkeys, not scripts. Asserted rather than assumed: if a
    // non-P2PKH address ever reaches here the fee is computed for the wrong
    // input size, and while `add_transparent_p2pkh_input` and the runtime
    // fee guard would both catch it, they would catch it as a confusing
    // downstream failure rather than a broken invariant. Raised in review of
    // #187.
    for utxo in utxos {
        debug_assert!(
            matches!(
                utxo.address,
                zcash_transparent::address::TransparentAddress::PublicKeyHash(_)
            ),
            "transparent recovery assumes P2PKH inputs; got {:?}",
            utxo.address
        );
    }
    let fee = zip317_sweep_fee(params, target_height, utxos.len())?;

    let Some(output) = total.checked_sub(fee).filter(|out| *out > 0) else {
        // An economic condition, not a misconfiguration: nothing the user
        // could pass would change it. Raised in review of #187.
        return Err(ZeckError::BelowDustThreshold(format!(
            "this wallet holds {total} zatoshis across {} output(s), which does not cover \
             the {fee} zatoshi network fee to move them. The funds are real but not \
             economically recoverable at the current fee.",
            utxos.len()
        )));
    };

    Ok(Some(TransparentSweepPlan {
        input_count: utxos.len(),
        total_input_zatoshis: total,
        fee_zatoshis: fee,
        output_zatoshis: output,
    }))
}

/// Refuse, before anything is broadcast, a destination a seedless sweep's
/// transparent leg cannot pay.
///
/// The imported sweep sends its Sapling legs first and its transparent leg
/// last, and only the transparent leg needs a Sapling receiver. An
/// Orchard-only address used to pass every check up to that point, so the
/// Sapling legs broadcast and the transparent funds were then left behind.
/// A key set with no transparent keys has no transparent leg and is not
/// constrained.
pub fn refuse_destination_the_transparent_leg_cannot_reach(
    keys: &argos_wallet_import::ImportedKeys,
    destination: &str,
    network: ZeckNetwork,
) -> ZeckResult<()> {
    if keys.transparent.is_empty() {
        return Ok(());
    }
    sapling_receiver(destination, network).map(|_| ())
}

/// Extract the Sapling receiver from a destination address.
///
/// The sweep pays into a Sapling output: a bundle with outputs but no
/// spends needs only an empty-tree anchor, whereas Orchard additionally
/// requires `orchard_anchor` / `ironwood_anchor` / bundle-type wiring under
/// NU6.3. Sapling is the conservative choice, and every UA that carries a
/// Sapling receiver — the common case — is reachable.
pub fn sapling_receiver(
    destination: &str,
    network: ZeckNetwork,
) -> ZeckResult<sapling::PaymentAddress> {
    // The receiver walk is shared with `sprout_sweep`; the error vocabulary
    // is not. This path returns typed variants and its tests match on them,
    // precisely so rewording a message cannot silently change behaviour.
    use crate::address::{find_sapling_receiver, ReceiverLookupError, SaplingReceiver};

    match find_sapling_receiver(destination, network) {
        Ok(SaplingReceiver::Found(address, _)) => Ok(address),
        Ok(SaplingReceiver::Malformed) => Err(ZeckError::MalformedReceiver(format!(
            "{destination} carries a Sapling receiver whose bytes do not decode. The \
             address is damaged rather than the wrong kind — re-copy it from your wallet \
             rather than looking for a different one."
        ))),
        Ok(SaplingReceiver::Absent) => Err(ZeckError::UnsupportedDestination),
        // A bare transparent address is refused for what it is, before any
        // question of networks: no t-address can ever receive shielded value,
        // so blaming the network setting would send the user to fix the one
        // thing that is not wrong.
        Err(ReceiverLookupError::Unsupported(_)) => Err(ZeckError::DestinationMustBeUnified),
        Err(ReceiverLookupError::IncorrectNetwork { expected, actual }) => {
            Err(ZeckError::WrongNetwork { expected, actual })
        }
        Err(ReceiverLookupError::NotAnAddress(err)) => Err(ZeckError::InvalidAddress(format!(
            "{destination} is not a Zcash address: {err}"
        ))),
    }
}

/// Build and sign a sweep of every supplied UTXO into one Sapling output.
///
/// Does not broadcast: the caller decides that, so a dry run and a real
/// sweep share this code and can only diverge in whether they transmit.
#[allow(clippy::too_many_arguments)]
pub fn build_sweep_transaction<P, SP, OP>(
    params: &P,
    target_height: zcash_protocol::consensus::BlockHeight,
    utxos: &[TransparentUtxo],
    keys: &[ImportedTransparentKey],
    plan: &TransparentSweepPlan,
    recipient: sapling::PaymentAddress,
    spend_prover: &SP,
    output_prover: &OP,
) -> ZeckResult<zcash_primitives::transaction::Transaction>
where
    P: zcash_protocol::consensus::Parameters,
    SP: sapling::prover::SpendProver,
    OP: sapling::prover::OutputProver,
{
    use crate::workspace::wallet_rng;
    use zcash_primitives::transaction::{
        builder::{BuildConfig, Builder, BundlePadding},
        fees::zip317::FeeRule,
    };
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};
    use zcash_transparent::builder::TransparentSigningSet;

    // No shielded spends, so the anchor is never checked against anything;
    // an empty tree is the correct value rather than a placeholder.
    let mut builder = Builder::new(
        params,
        target_height,
        BuildConfig::Standard {
            sapling_anchor: Some(sapling::Anchor::empty_tree()),
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );

    // Index keys by address so each input is matched to the key that
    // actually controls it. Looking up by address rather than by position
    // is what keeps this correct when a wallet holds several UTXOs on one
    // address, or addresses with no UTXOs at all.
    let mut signing_set = TransparentSigningSet::new();
    let mut pubkey_for_address = std::collections::HashMap::new();
    for key in keys {
        let pubkey = signing_set.add_key(key.signing_key_copy());
        pubkey_for_address.insert(key.address, pubkey);
    }

    for utxo in utxos {
        let pubkey = pubkey_for_address.get(&utxo.address).ok_or_else(|| {
            ZeckError::Internal(format!(
                "no spending key for UTXO on address {:?}; refusing to build a transaction \
                 that cannot be signed",
                utxo.address
            ))
        })?;
        builder
            .add_transparent_p2pkh_input(*pubkey, utxo.outpoint.clone(), utxo.txout.clone())
            .map_err(|err| ZeckError::Wallet(format!("adding transparent input: {err:?}")))?;
    }

    let output_value = Zatoshis::from_u64(plan.output_zatoshis)
        .map_err(|_| ZeckError::Internal("planned output value is out of range".to_owned()))?;
    builder
        .add_sapling_output::<zcash_primitives::transaction::fees::zip317::FeeError>(
            // No outgoing viewing key: nothing in this wallet should be
            // able to decrypt the output afterwards, and there is no
            // account here whose OVK would be meaningful.
            None,
            recipient,
            output_value,
            MemoBytes::empty(),
        )
        .map_err(|err| ZeckError::Wallet(format!("adding the Sapling output: {err:?}")))?;

    let fee_rule = FeeRule::standard();

    // The planner and the builder must agree on the fee. They compute it
    // from the same rule over the same bundle shape, so a mismatch means a
    // bug in one of them — and the user would silently overpay or have the
    // transaction rejected. Check rather than assume.
    let builder_fee = builder
        .get_fee(&fee_rule)
        .map_err(|err| ZeckError::Wallet(format!("recomputing the fee failed: {err:?}")))?;
    if u64::from(builder_fee) != plan.fee_zatoshis {
        return Err(ZeckError::Internal(format!(
            "planned fee {} does not match the builder's fee {}; refusing to sign",
            plan.fee_zatoshis,
            u64::from(builder_fee)
        )));
    }

    let result = builder
        .build(
            &signing_set,
            // No shielded spends: no Sapling or Orchard spend authority
            // is required, which is exactly why a transparent-only wallet
            // needs no account.
            &[],
            &[],
            wallet_rng(),
            spend_prover,
            output_prover,
            &fee_rule,
        )
        .map_err(|err| ZeckError::Wallet(format!("building the sweep transaction: {err:?}")))?;

    crate::nu7_limits::validate_transaction(params, target_height, result.transaction())?;
    Ok(result.transaction().clone())
}

/// Outcome of a transparent sweep submission, including uncertain replies.
#[derive(Debug, Clone)]
pub struct TransparentSweepOutcome {
    pub transaction: TxBroadcastResult,
    pub disposition: crate::broadcast::SubmissionDisposition,
    pub plan: TransparentSweepPlan,
    pub destination: String,
}

/// Connect, validate the endpoint against `network`, and report what the
/// imported transparent keys can spend.
pub async fn scan_transparent_only(
    keys: &[ImportedTransparentKey],
    network: ZeckNetwork,
    lightwalletd_url: &str,
) -> ZeckResult<TransparentScanReport> {
    let (mut client, _endpoint, info) =
        crate::lightwalletd::probe_lightwalletd_endpoints_with_retry(lightwalletd_url).await?;
    crate::lightwalletd::validate_lightwalletd_network(network, &info)?;

    let chain_tip = u32::try_from(info.block_height)
        .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))?;
    let utxos = fetch_transparent_utxos(&mut client, keys, network).await?;
    Ok(summarize(&utxos, keys.len(), chain_tip, network))
}

/// Refuse a transparent sweep whose fee, with what the sweep has already
/// paid, is over `--max-fee`.
pub(crate) fn check_transparent_fee(
    fee_zatoshis: u64,
    input_count: usize,
    prior_fee_zatoshis: u64,
    max_fee_zatoshis: Option<u64>,
) -> ZeckResult<()> {
    let total = crate::service::checked_fee_total(prior_fee_zatoshis, fee_zatoshis)?;
    match max_fee_zatoshis {
        Some(cap) if total > cap && prior_fee_zatoshis == 0 => {
            Err(ZeckError::MaxFeeExceeded(format!(
                "the sweep needs a {fee_zatoshis} zatoshi fee for {input_count} input(s), \
                 above the {cap} zatoshi limit. Nothing was signed or broadcast."
            )))
        }
        Some(cap) if total > cap => Err(ZeckError::MaxFeeExceeded(format!(
            "the transparent sweep needs a {fee_zatoshis} zatoshi fee for {input_count} \
             input(s); with {prior_fee_zatoshis} already paid by this sweep's earlier \
             transactions the total is {total}, above the {cap} zatoshi limit. Nothing was \
             signed or broadcast for it."
        ))),
        _ => Ok(()),
    }
}

/// Blocks the chain may advance between a CLI quote and its execution. The
/// transaction is built at the execute-time height, so it carries a full
/// expiry window from then; this bound only limits how stale the reviewed
/// UTXO set and fee may be. This chain-drift bound is independent of the
/// transaction expiry delta and remains 20 at NU7; its expected elapsed
/// lifetime becomes shorter with 25-second blocks.
pub const TRANSPARENT_QUOTE_MAX_AGE_BLOCKS: u32 = 20;

/// A quote stays executable while the consensus branch (and so the
/// transaction version and fee rule) is unchanged and the tip has moved by
/// at most [`TRANSPARENT_QUOTE_MAX_AGE_BLOCKS`] in either direction.
pub(crate) fn require_quote_height_current(
    network: ZeckNetwork,
    quoted_target: u32,
    current_target: u32,
) -> ZeckResult<()> {
    use zcash_protocol::consensus::{BlockHeight, BranchId};

    let params = crate::workspace::consensus_network(network);
    if BranchId::for_height(&params, BlockHeight::from_u32(quoted_target))
        != BranchId::for_height(&params, BlockHeight::from_u32(current_target))
    {
        return Err(ZeckError::StaleSweepProposal(
            "a network upgrade activated after review; quote again".to_owned(),
        ));
    }
    if current_target.abs_diff(quoted_target) > TRANSPARENT_QUOTE_MAX_AGE_BLOCKS {
        return Err(ZeckError::StaleSweepProposal(format!(
            "the transparent sweep quote is more than {TRANSPARENT_QUOTE_MAX_AGE_BLOCKS} blocks old; quote again"
        )));
    }
    Ok(())
}

/// Execute a standalone transparent quote only while its exact reviewed
/// coins, fee, output, and target height remain current. When no ceiling was
/// supplied, the quoted fee is the maximum authorized by this review.
#[allow(clippy::too_many_arguments)]
pub async fn sweep_transparent_only_from_quote(
    store: &mut impl BroadcastStore,
    keys: &[ImportedTransparentKey],
    network: ZeckNetwork,
    lightwalletd_url: &str,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
    quote: &TransparentSweepQuote,
) -> ZeckResult<Option<TransparentSweepOutcome>> {
    use zcash_protocol::consensus::BlockHeight;

    sapling_receiver(destination, network)?;
    if network != quote.network || transparent_key_addresses(keys, network) != quote.key_addresses {
        return Err(ZeckError::StaleSweepProposal(
            "transparent sweep source keys or network changed after review".to_owned(),
        ));
    }

    let (mut client, _endpoint, info) =
        crate::lightwalletd::probe_lightwalletd_endpoints_with_retry(lightwalletd_url).await?;
    crate::lightwalletd::validate_lightwalletd_network(network, &info)?;
    let chain_tip = u32::try_from(info.block_height)
        .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))?;
    let current_target = chain_tip.saturating_add(1);
    require_quote_height_current(network, quote.target_height, current_target)?;
    let current_utxos = fetch_transparent_utxos(&mut client, keys, network).await?;
    if transparent_input_set_identity(&current_utxos)
        != transparent_input_set_identity(&quote.utxos)
    {
        return Err(ZeckError::StaleSweepProposal(
            "selected sweep inputs changed after review; quote again before signing".to_owned(),
        ));
    }
    let Some(reviewed) = quote.plan.as_ref() else {
        return Ok(None);
    };
    // The plan actually built, at the execute-time height. Its fee is
    // compared with the reviewed quote's fee before anything is signed.
    let Some(built) = plan_sweep(
        &crate::workspace::consensus_network(network),
        BlockHeight::from_u32(current_target),
        &current_utxos,
    )?
    else {
        return Err(ZeckError::StaleSweepProposal(
            "the reviewed transparent inputs no longer cover a sweep; quote again".to_owned(),
        ));
    };
    sweep_transparent_only_reviewed(
        store,
        keys,
        network,
        lightwalletd_url,
        destination,
        Some(max_fee_zatoshis.unwrap_or(reviewed.fee_zatoshis)),
        0,
        Some(reviewed.fee_zatoshis),
        Some((&current_utxos, &built, current_target)),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn sweep_transparent_only_reviewed(
    store: &mut impl BroadcastStore,
    keys: &[ImportedTransparentKey],
    network: ZeckNetwork,
    lightwalletd_url: &str,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
    prior_fee_zatoshis: u64,
    reviewed_fee_zatoshis: Option<u64>,
    reviewed_inputs: Option<(&[TransparentUtxo], &TransparentSweepPlan, u32)>,
) -> ZeckResult<Option<TransparentSweepOutcome>> {
    use zcash_proofs::prover::LocalTxProver;
    use zcash_protocol::consensus::BlockHeight;

    // Resolve the destination before touching the network: a bad address
    // should fail instantly, not after a scan.
    let recipient = sapling_receiver(destination, network)?;

    // The reviewed fee against the plan that will be built, before any
    // network or signing work, and before the fee ceiling: a changed fee is
    // FeeQuoteChanged, never MaxFeeExceeded.
    if let (Some(reviewed), Some((_, plan, _))) = (reviewed_fee_zatoshis, reviewed_inputs) {
        if reviewed != plan.fee_zatoshis {
            return Err(ZeckError::FeeQuoteChanged {
                reviewed,
                current: plan.fee_zatoshis,
            });
        }
    }

    let (mut client, _endpoint, info) =
        crate::lightwalletd::probe_lightwalletd_endpoints_with_retry(lightwalletd_url).await?;
    crate::lightwalletd::validate_lightwalletd_network(network, &info)?;

    let chain_tip = u32::try_from(info.block_height)
        .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))?;
    let params = crate::workspace::consensus_network(network);
    let target_height = execution_target_height(
        BlockHeight::from_u32(chain_tip.saturating_add(1)),
        reviewed_inputs.map(|(_, _, height)| BlockHeight::from_u32(height)),
    );
    let (utxos, plan) = if let Some((utxos, plan, _)) = reviewed_inputs {
        (utxos.to_vec(), plan.clone())
    } else {
        let utxos = fetch_transparent_utxos(&mut client, keys, network).await?;
        let Some(plan) = plan_sweep(&params, target_height, &utxos)? else {
            return Ok(None);
        };
        (utxos, plan)
    };

    if let Some(reviewed) = reviewed_fee_zatoshis {
        if reviewed != plan.fee_zatoshis {
            return Err(ZeckError::FeeQuoteChanged {
                reviewed,
                current: plan.fee_zatoshis,
            });
        }
    }

    check_transparent_fee(
        plan.fee_zatoshis,
        plan.input_count,
        prior_fee_zatoshis,
        max_fee_zatoshis,
    )?;

    let prover = LocalTxProver::bundled();
    let tx = build_sweep_transaction(
        &params,
        target_height,
        &utxos,
        keys,
        &plan,
        recipient,
        &prover,
        &prover,
    )?;

    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|err| ZeckError::TransactionBuild(format!("serializing the sweep: {err}")))?;

    let prepared = PreparedTransaction {
        txid: tx.txid(),
        raw_tx: raw,
        fee_zatoshis: plan.fee_zatoshis,
        expiry_height: Some(u32::from(tx.expiry_height())),
    };
    // Proving can span a consensus boundary; the signed transaction must still
    // be mineable at the next block before any prepared record or network send.
    let tip = crate::nu7::validated_tip_from_client(&mut client, network).await?;
    crate::nu7::validate_transaction_for_tip(network, tip, &tx)?;
    Ok(Some(
        submit_transparent_prepared(
            store,
            &mut LightwalletdSubmitter {
                client: &mut client,
            },
            prepared,
            plan,
            destination,
        )
        .await?,
    ))
}

fn execution_target_height(
    current: zcash_protocol::consensus::BlockHeight,
    reviewed: Option<zcash_protocol::consensus::BlockHeight>,
) -> zcash_protocol::consensus::BlockHeight {
    // The caller validated this concrete target with the reviewed UTXOs and
    // version. A newer lightwalletd tip must not alter the signed transaction
    // after the final quote comparison.
    reviewed.unwrap_or(current)
}

async fn submit_transparent_prepared<S: BroadcastStore, N: TxSubmitter>(
    store: &mut S,
    submitter: &mut N,
    prepared: PreparedTransaction,
    plan: TransparentSweepPlan,
    destination: &str,
) -> ZeckResult<TransparentSweepOutcome> {
    let submitted = submit_prepared_transaction(
        store,
        submitter,
        prepared,
        std::time::Duration::from_secs(30),
    )
    .await?;
    Ok(TransparentSweepOutcome {
        transaction: TxBroadcastResult {
            source_account: 0,
            txid: Some(submitted.txid.to_string()),
            status: submitted.state,
            fee_zatoshis: submitted.fee_zatoshis,
            detail: format!(
                "transparent sweep submission: {:?}{}",
                submitted.disposition,
                submitted
                    .persistence_warning
                    .as_ref()
                    .map(|warning| format!(" Persistence warning: {warning}"))
                    .unwrap_or_default()
            ),
            confirmed_height: None,
            safe_to_discard: false,
        },
        disposition: submitted.disposition,
        plan,
        destination: destination.to_owned(),
    })
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    pub fn utxo(address: TransparentAddress, value: u64, txid_byte: u8) -> TransparentUtxo {
        TransparentUtxo {
            outpoint: OutPoint::new([txid_byte; 32], 0),
            txout: TxOut::new(
                Zatoshis::from_u64(value).expect("valid amount"),
                address.script().into(),
            ),
            address,
            height: 100,
        }
    }

    pub fn addr(byte: u8) -> TransparentAddress {
        TransparentAddress::PublicKeyHash([byte; 20])
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;

    #[test]
    fn same_outpoint_and_value_with_conflicting_reported_script_is_rejected() {
        let address = addr(1);
        let expected_script: zcash_transparent::address::Script = address.script().into();
        let entry = zcash_client_backend::proto::service::GetAddressUtxosReply {
            address: encode_transparent_address(&address, ZeckNetwork::Mainnet),
            txid: vec![0xAA; 32],
            index: 0,
            script: expected_script.0 .0.clone(),
            value_zat: 100_000,
            height: 100,
        };
        let first = super::parse_reported_utxo(entry.clone(), address)
            .expect("matching script")
            .expect("valid UTXO");
        let mut conflicting = entry;
        conflicting.script[0] ^= 1;
        let error = super::parse_reported_utxo(conflicting, address)
            .expect_err("the same outpoint cannot claim a different script");
        assert!(error.to_string().contains("script"), "{error}");
        assert_eq!(first.outpoint, OutPoint::new([0xAA; 32], 0));
    }

    #[test]
    fn balances_are_summed_per_address_not_per_utxo() {
        // The bug this guards against is reporting a wallet's largest
        // single UTXO as its balance, which understates recoverable funds.
        let utxos = vec![utxo(addr(1), 100, 0xAA), utxo(addr(1), 250, 0xBB)];
        let report = summarize(&utxos, 1, 500, ZeckNetwork::Mainnet);

        assert_eq!(report.total_zatoshis, 350);
        assert_eq!(report.funded.len(), 1, "one address, not one row per UTXO");
        assert_eq!(report.funded[0].zatoshis, 350);
        assert_eq!(report.funded[0].utxo_count, 2);
    }

    #[test]
    fn repeated_outpoint_is_counted_only_once() {
        // A lightwalletd batch can repeat the same outpoint. It is still one
        // spendable coin, and quoting it twice would overstate recovery.
        let coin = utxo(addr(1), 100_000, 0xAA);
        let report = summarize(&[coin.clone(), coin], 1, 500, ZeckNetwork::Mainnet);
        assert_eq!(report.total_zatoshis, 100_000);
        assert_eq!(report.funded[0].utxo_count, 1);
    }

    #[test]
    fn addresses_are_reported_most_valuable_first() {
        let utxos = vec![
            utxo(addr(1), 100, 0xAA),
            utxo(addr(2), 900, 0xBB),
            utxo(addr(3), 500, 0xCC),
        ];
        let report = summarize(&utxos, 3, 500, ZeckNetwork::Mainnet);
        let values: Vec<u64> = report.funded.iter().map(|b| b.zatoshis).collect();
        assert_eq!(values, vec![900, 500, 100]);
    }

    #[test]
    fn an_empty_wallet_reports_zero_rather_than_failing() {
        // A genuinely empty wallet is a valid answer, and it must be
        // distinguishable from an error — a recovery user reads a failure
        // as "try again" and a zero as "there is nothing here".
        let report = summarize(&[], 103, 500, ZeckNetwork::Mainnet);
        assert_eq!(report.total_zatoshis, 0);
        assert!(report.funded.is_empty());
        assert_eq!(
            report.addresses_checked, 103,
            "the report must still say how many addresses were looked at"
        );
    }

    #[test]
    fn unfunded_addresses_are_omitted_from_the_funded_list() {
        // A 103-address wallet with one funded address should not print
        // 102 zero rows.
        let utxos = vec![utxo(addr(7), 42, 0xAA)];
        let report = summarize(&utxos, 103, 500, ZeckNetwork::Mainnet);
        assert_eq!(report.funded.len(), 1, "only the funded address is listed");
        assert_eq!(
            report.addresses_checked, 103,
            "but the count of addresses actually checked is preserved, so the \
             user can tell an empty wallet from a partial scan"
        );
    }
}

#[cfg(test)]
mod sweep_tests {
    use super::tests_support::*;
    use super::*;
    use crate::TxLifecycleState;
    use zcash_protocol::consensus::{BlockHeight, MAIN_NETWORK};

    #[test]
    fn reviewed_direct_build_keeps_validated_height_across_version_boundary() {
        use zcash_primitives::transaction::TxVersion;
        use zcash_protocol::consensus::{BranchId, NetworkUpgrade, Parameters as _};

        let activation = MAIN_NETWORK.activation_height(NetworkUpgrade::Nu5).unwrap();
        let reviewed = BlockHeight::from_u32(u32::from(activation) - 1);
        let later = activation;
        let selected = execution_target_height(later, Some(reviewed));
        assert_eq!(selected, reviewed);
        assert_eq!(execution_target_height(later, None), later);
        assert_ne!(
            TxVersion::suggested_for_branch(BranchId::for_height(&MAIN_NETWORK, selected)),
            TxVersion::suggested_for_branch(BranchId::for_height(&MAIN_NETWORK, later)),
        );
    }

    #[test]
    fn quote_survives_a_new_block_but_not_a_branch_change_or_old_age() {
        use zcash_protocol::consensus::{NetworkUpgrade, Parameters as _};

        let network = ZeckNetwork::Mainnet;
        let activation = u32::from(MAIN_NETWORK.activation_height(NetworkUpgrade::Nu5).unwrap());
        let quoted = activation + 1_000;
        // A block landing between quote and execute is ordinary.
        assert!(require_quote_height_current(network, quoted, quoted).is_ok());
        assert!(require_quote_height_current(network, quoted, quoted + 1).is_ok());
        assert!(require_quote_height_current(
            network,
            quoted,
            quoted + TRANSPARENT_QUOTE_MAX_AGE_BLOCKS
        )
        .is_ok());
        // Too old.
        assert!(matches!(
            require_quote_height_current(
                network,
                quoted,
                quoted + TRANSPARENT_QUOTE_MAX_AGE_BLOCKS + 1
            ),
            Err(ZeckError::StaleSweepProposal(_))
        ));
        // A consensus branch change invalidates the reviewed version.
        assert!(matches!(
            require_quote_height_current(network, activation - 1, activation),
            Err(ZeckError::StaleSweepProposal(_))
        ));
    }

    #[test]
    fn nu7_activation_invalidates_direct_quotes_on_both_networks() {
        for network in [ZeckNetwork::Mainnet, ZeckNetwork::Testnet] {
            let activation = crate::nu7::activation_height(network).expect("NU7 schedule");
            assert!(matches!(
                require_quote_height_current(network, activation - 1, activation),
                Err(ZeckError::StaleSweepProposal(_))
            ));
            assert!(require_quote_height_current(network, activation, activation + 1).is_ok());
        }
    }

    #[tokio::test]
    async fn reviewed_transparent_fee_is_checked_against_the_built_plan_before_network() {
        use crate::broadcast::DurableBroadcastLog;

        let mut secret = secp256k1::SecretKey::from_secret_bytes([0x42; 32]).unwrap();
        let key = crate::imported::ImportedTransparentKey::new(&mut secret, addr(1));
        let utxos = vec![utxo(addr(1), 1_000_000, 9)];
        let built = plan_sweep(&MAIN_NETWORK, height(), &utxos)
            .unwrap()
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut log = DurableBroadcastLog::open(dir.path().join("log.jsonl")).unwrap();
        // The session endpoint is unroutable: the comparison must come first.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            sweep_transparent_only_reviewed(
                &mut log,
                &[key],
                ZeckNetwork::Mainnet,
                "https://127.0.0.1:1",
                &super::destination_tests::unified_address_for(
                    zcash_protocol::consensus::NetworkType::Main,
                ),
                None,
                0,
                Some(built.fee_zatoshis + 5_000),
                Some((&utxos, &built, u32::from(height()))),
            ),
        )
        .await
        .expect("no network before the reviewed-fee check");
        assert!(
            matches!(
                result,
                Err(ZeckError::FeeQuoteChanged { reviewed, current })
                    if reviewed == built.fee_zatoshis + 5_000 && current == built.fee_zatoshis
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn transparent_record_keeps_txid_fee_and_warning_when_final_sync_fails() {
        use crate::broadcast::{BroadcastStore, DurableBroadcastLog};
        use crate::test_support::{empty_v5_prepared, AcceptingSubmitter, FinalTransitionFails};

        let prepared = empty_v5_prepared(100, 10_000);
        let txid = prepared.txid;
        let plan = TransparentSweepPlan {
            input_count: 1,
            total_input_zatoshis: 30_000,
            fee_zatoshis: 10_000,
            output_zatoshis: 20_000,
        };
        let dir = tempfile::tempdir().unwrap();
        let mut store = FinalTransitionFails(
            DurableBroadcastLog::open(dir.path().join("broadcasts-v1.jsonl")).unwrap(),
        );
        let result = submit_transparent_prepared(
            &mut store,
            &mut AcceptingSubmitter::default(),
            prepared,
            plan,
            "destination",
        )
        .await
        .unwrap();
        assert_eq!(result.transaction.txid, Some(txid.to_string()));
        assert_eq!(result.transaction.fee_zatoshis, 10_000);
        assert_eq!(
            result.transaction.status,
            TxLifecycleState::SubmissionUnknown
        );
        assert!(result.transaction.detail.contains("final sync failed"));
        assert_eq!(
            store.latest(txid).unwrap().state,
            TxLifecycleState::SubmissionUnknown
        );
    }

    #[tokio::test]
    async fn transparent_transport_failure_returns_known_txid_and_unknown_state() {
        use crate::broadcast::DurableBroadcastLog;
        use crate::models::TxLifecycleState;
        use crate::test_support::{empty_v5_prepared, LostReplySubmitter};

        let prepared = empty_v5_prepared(100, 10_000);
        let txid = prepared.txid;
        let plan = TransparentSweepPlan {
            input_count: 1,
            total_input_zatoshis: 30_000,
            fee_zatoshis: 10_000,
            output_zatoshis: 20_000,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broadcasts-v1.jsonl");
        let mut log = DurableBroadcastLog::open(&path).unwrap();
        let outcome = submit_transparent_prepared(
            &mut log,
            &mut LostReplySubmitter,
            prepared,
            plan,
            "destination",
        )
        .await
        .unwrap();
        assert_eq!(
            outcome.transaction.txid.as_deref(),
            Some(txid.to_string().as_str())
        );
        assert_eq!(
            outcome.transaction.status,
            TxLifecycleState::SubmissionUnknown
        );
        assert_eq!(outcome.transaction.fee_zatoshis, 10_000);
        assert!(
            path.exists(),
            "raw bytes must be durably stored before network I/O"
        );
    }

    fn height() -> BlockHeight {
        BlockHeight::from_u32(3_000_000)
    }

    #[test]
    fn canonical_address_identity_is_a_tagged_hash_not_debug_text() {
        let mut p2pkh = [7u8; 21];
        p2pkh[0] = 0;
        let mut p2sh = [7u8; 21];
        p2sh[0] = 1;
        assert_eq!(
            transparent_address_identity(&TransparentAddress::PublicKeyHash([7; 20])),
            p2pkh
        );
        assert_eq!(
            transparent_address_identity(&TransparentAddress::ScriptHash([7; 20])),
            p2sh
        );
    }

    #[test]
    fn an_empty_wallet_has_nothing_to_plan() {
        assert!(plan_sweep(&MAIN_NETWORK, height(), &[])
            .expect("planning an empty wallet is not an error")
            .is_none());
    }

    #[test]
    fn the_plan_conserves_value_exactly() {
        // inputs = fee + output, with no remainder. A sweep that silently
        // dropped a few zatoshis would be burning the user's money.
        let utxos = vec![utxo(addr(1), 500_000, 0xAA), utxo(addr(2), 250_000, 0xBB)];
        let plan = plan_sweep(&MAIN_NETWORK, height(), &utxos)
            .expect("planning should succeed")
            .expect("a funded wallet must produce a plan");

        assert_eq!(plan.input_count, 2);
        assert_eq!(plan.total_input_zatoshis, 750_000);
        assert_eq!(
            plan.output_zatoshis + plan.fee_zatoshis,
            plan.total_input_zatoshis,
            "inputs must equal fee plus output, with nothing unaccounted for"
        );
    }

    #[test]
    fn conflicting_duplicate_outpoint_cannot_be_planned() {
        let first = utxo(addr(1), 500_000, 0xAA);
        let conflict = utxo(addr(2), 700_000, 0xAA);
        let error = plan_sweep(&MAIN_NETWORK, height(), &[first, conflict])
            .expect_err("one outpoint cannot have two owners or amounts");
        assert!(error.to_string().contains("outpoint"), "{error}");
    }

    #[test]
    fn the_fee_grows_with_the_number_of_inputs() {
        // A 103-address wallet pays for 103 inputs. If the fee were flat,
        // the transaction would be underpaid and rejected — after the user
        // was told it would succeed.
        let few = vec![utxo(addr(1), 10_000_000, 0xAA)];
        let many: Vec<_> = (0u8..40).map(|i| utxo(addr(i), 10_000_000, i)).collect();

        let small = plan_sweep(&MAIN_NETWORK, height(), &few).unwrap().unwrap();
        let large = plan_sweep(&MAIN_NETWORK, height(), &many).unwrap().unwrap();

        assert!(
            large.fee_zatoshis > small.fee_zatoshis,
            "40 inputs must cost more than 1: got {} vs {}",
            large.fee_zatoshis,
            small.fee_zatoshis
        );
    }

    #[test]
    fn dust_is_refused_with_an_explanation_rather_than_swept() {
        // The failure mode: build a transaction whose output is zero or
        // negative, get it rejected by the network, and leave the user
        // thinking recovery failed for a mysterious reason. Say plainly
        // that the funds exist but cannot pay their own way out.
        let utxos = vec![utxo(addr(1), 100, 0xAA)];
        let err = plan_sweep(&MAIN_NETWORK, height(), &utxos)
            .expect_err("dust must not produce a spendable plan");
        let rendered = err.to_string();
        assert!(
            rendered.contains("does not cover"),
            "the refusal must explain the shortfall, got: {rendered}"
        );
        assert!(
            rendered.contains("real but not"),
            "the refusal must confirm the funds exist, got: {rendered}"
        );
    }
}

#[cfg(test)]
mod destination_tests {
    use super::*;
    use crate::models::ZeckNetwork;

    /// A UA with no Sapling receiver must be refused *before* anything is
    /// signed, with an error the user can act on — not fail deep inside
    /// the builder with a type error.
    #[test]
    fn a_transparent_only_destination_is_refused_with_guidance() {
        // A bare t-address: valid, but it has no Sapling receiver.
        let err = sapling_receiver("t1UE73p3WKJRqjMTyFqRKXieX9FkWTNvZhm", ZeckNetwork::Mainnet)
            .expect_err("a transparent destination has no Sapling receiver");
        let rendered = err.to_string();
        assert!(
            rendered.contains("Sapling") || rendered.contains("destination"),
            "the refusal must name the problem, got: {rendered}"
        );
    }

    #[test]
    fn garbage_is_rejected_rather_than_parsed_into_something() {
        assert!(sapling_receiver("not-an-address", ZeckNetwork::Mainnet).is_err());
    }

    /// Asserts the *variant*, not merely that it errs.
    ///
    /// Raised in review of #187 and never addressed when that PR was folded
    /// into #189: this fed a bare t-address and asserted `.is_err()`, which
    /// passes on `DestinationMustBeUnified` — thrown before any network
    /// logic runs. So the test named for a network mismatch never reached
    /// the network check, and the genuinely dangerous case, a mainnet
    /// *unified* address used on a testnet sweep, had no coverage at all.
    ///
    /// Pinning the variant at least makes the test honest about which rule
    /// rejects a t-address. The mainnet-UA-on-testnet case still wants a
    /// real encoded UA fixture; see the note below.
    /// The three refusals must be distinguishable by variant, not just by
    /// prose. Callers and tests both matched on message text before, which
    /// is how a t-address ended up asserted as a network failure.
    /// Build a real unified address, in-process, from a real Sapling
    /// receiver.
    ///
    /// Constructed rather than pasted. Every hand-written address fixture in
    /// this session turned out to be invalid — one `zs1…` that decoded to
    /// nothing, one `t1…` that was not an address at all — and each one made
    /// a test pass for the wrong reason. Deriving the receiver from a key
    /// and letting `zcash_address` encode it means the fixture is valid by
    /// construction, and the assertion below that it decodes proves it.
    pub(super) fn unified_address_for(network: zcash_protocol::consensus::NetworkType) -> String {
        use zcash_address::unified::{Address, Encoding, Receiver};

        let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&[0x7u8; 32])
            .expect("valid fixture Sapling key");
        let (_, payment_address) = extsk.default_address();

        let ua = Address::try_from_items(
            zcash_address::unified::Revision::R0,
            vec![Receiver::Sapling(payment_address.to_bytes())]
                .into_iter()
                .map(zcash_address::unified::Uitem::Data)
                .collect(),
        )
        .expect("a Sapling-only unified address is valid under ZIP 316");
        ua.encode(&network)
    }

    /// The case Kristi's review named and nothing covered: a mainnet
    /// *unified* address used for a testnet sweep.
    ///
    /// The old test fed a bare t-address, which is rejected as non-unified
    /// before any network logic runs, so the network check itself was never
    /// reached. This one gets past that rule and asserts the network
    /// variant specifically — sending real funds to an address that cannot
    /// be spent on the chain they were broadcast to is the failure it
    /// guards.
    #[test]
    fn a_mainnet_unified_address_is_refused_for_a_testnet_sweep() {
        let mainnet_ua = unified_address_for(zcash_protocol::consensus::NetworkType::Main);

        // It must genuinely be a usable mainnet destination, or the test
        // below would pass for the wrong reason all over again.
        sapling_receiver(&mainnet_ua, ZeckNetwork::Mainnet)
            .expect("the fixture must be a valid mainnet destination");

        let err = match sapling_receiver(&mainnet_ua, ZeckNetwork::Testnet) {
            Ok(_) => panic!("a mainnet unified address must not be accepted on testnet"),
            Err(err) => err,
        };
        assert!(
            matches!(err, ZeckError::WrongNetwork { .. }),
            "expected the network check to fire, not the unified-only rule; got {err:?}"
        );
    }

    #[test]
    fn dust_is_an_economic_refusal_not_a_configuration_error() {
        // A wallet worth less than its own fee is not misconfigured; no
        // argument the user could pass would change the outcome.
        let utxos = vec![tests_support::utxo(tests_support::addr(0x11), 1, 0xAA)];
        match plan_sweep(
            &zcash_protocol::consensus::MAIN_NETWORK,
            zcash_protocol::consensus::BlockHeight::from_u32(2_500_000),
            &utxos,
        ) {
            Ok(_) => panic!("a 1-zatoshi wallet cannot cover its fee"),
            Err(err) => assert!(
                matches!(err, ZeckError::BelowDustThreshold(_)),
                "dust is an economic condition, not an InvalidConfig; got {err:?}"
            ),
        }
    }

    #[test]
    fn a_transparent_destination_is_refused_for_not_being_unified() {
        let err =
            match sapling_receiver("t1UE73p3WKJRqjMTyFqRKXieX9FkWTNvZhm", ZeckNetwork::Testnet) {
                Ok(_) => panic!("a t-address must not be accepted as a sweep destination"),
                Err(err) => err,
            };
        assert!(
            matches!(err, ZeckError::DestinationMustBeUnified),
            "a t-address is refused for not being unified, not for anything about \
             networks or receivers; got {err:?}"
        );
    }
}

#[cfg(test)]
mod cumulative_fee_tests {
    use super::*;

    /// The transparent leg of an imported sweep runs after its Sapling
    /// transactions, and must count what they already paid.
    #[test]
    fn the_transparent_leg_counts_fees_already_paid() {
        assert!(check_transparent_fee(3_000, 2, 0, Some(5_000)).is_ok());
        let err = check_transparent_fee(3_000, 2, 4_000, Some(5_000))
            .expect_err("4,000 already paid plus 3,000 is over 5,000");
        let text = err.to_string();
        assert!(text.contains("4000 already paid"), "{text}");
        assert!(text.contains("Nothing was signed"), "{text}");
        assert!(
            check_transparent_fee(3_000, 2, 9_999_999, None).is_ok(),
            "no cap, no limit"
        );
    }
}

#[cfg(test)]
mod seedless_destination_tests {
    use super::*;
    use crate::models::ZeckNetwork;

    /// An Orchard-only unified address, built from a key rather than pasted,
    /// as `destination_tests` does for Sapling.
    fn orchard_only_ua() -> String {
        use zcash_address::unified::{Address, Encoding, Receiver};
        let sk = orchard::keys::SpendingKey::from_bytes([7u8; 32]).expect("a valid spending key");
        let fvk = orchard::keys::FullViewingKey::from(&sk);
        let address = fvk.address_at(0u32, orchard::keys::Scope::External);
        Address::try_from_items(
            zcash_address::unified::Revision::R0,
            vec![Receiver::Orchard(address.to_raw_address_bytes())]
                .into_iter()
                .map(zcash_address::unified::Uitem::Data)
                .collect(),
        )
        .expect("an Orchard-only unified address is valid under ZIP 316")
        .encode(&zcash_protocol::consensus::NetworkType::Main)
    }

    fn with_transparent_key() -> argos_wallet_import::ImportedKeys {
        argos_wallet_import::ImportedKeys {
            transparent: vec![argos_wallet_import::keys::TransparentKey {
                secret: secrecy::Secret::new([1u8; 32]),
                provenance: argos_wallet_import::Provenance::Standalone,
                created_at: None,
            }],
            ..Default::default()
        }
    }

    /// Reported against #231: an Orchard-only address passes the sweep's
    /// destination check, the Sapling leg broadcasts, and only then does the
    /// transparent leg fail — a half-finished sweep with the transparent
    /// funds stranded. Refused before anything moves instead.
    #[test]
    fn a_destination_the_transparent_leg_cannot_reach_is_refused_up_front() {
        let err = refuse_destination_the_transparent_leg_cannot_reach(
            &with_transparent_key(),
            &orchard_only_ua(),
            ZeckNetwork::Mainnet,
        )
        .expect_err("transparent funds cannot reach an Orchard-only address");
        assert!(err.to_string().contains("Sapling"), "{err}");

        // With no transparent keys there is no transparent leg, and Orchard
        // is a fine destination for the Sapling legs.
        refuse_destination_the_transparent_leg_cannot_reach(
            &argos_wallet_import::ImportedKeys::default(),
            &orchard_only_ua(),
            ZeckNetwork::Mainnet,
        )
        .expect("no transparent leg, nothing to refuse");
    }
}
