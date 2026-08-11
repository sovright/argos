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

use sapling_crypto as sapling;
use tonic::transport::Channel;
use tracing::warn;
use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, GetAddressUtxosArg,
};
use zcash_protocol::value::Zatoshis;
use zcash_transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};

use crate::{
    error::{ZeckError, ZeckResult},
    imported::{encode_transparent_address, ImportedTransparentKey},
    models::ZeckNetwork,
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

            // A negative value is a misbehaving server. Coercing it to
            // zero would hide that; skipping it loudly does not.
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
                    continue;
                }
            };

            let txid: [u8; 32] = match entry.txid.as_slice().try_into() {
                Ok(t) => t,
                Err(_) => {
                    warn!(
                        "lightwalletd returned a {}-byte txid for {}; skipping",
                        entry.txid.len(),
                        entry.address
                    );
                    continue;
                }
            };
            let index = match u32::try_from(entry.index) {
                Ok(i) => i,
                Err(_) => {
                    warn!(
                        "lightwalletd returned a negative output index for {}; skipping",
                        entry.address
                    );
                    continue;
                }
            };

            // Derive the scriptPubKey from the address we already hold
            // rather than adopting `entry.script` from the server. They
            // should agree, but only one of them is something we can
            // verify — and a script we accept unchecked is a script we
            // would later sign against.
            utxos.push(TransparentUtxo {
                outpoint: OutPoint::new(txid, index),
                txout: TxOut::new(value, address.script().into()),
                address,
                height: entry.height,
            });
        }
    }

    Ok(utxos)
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

    for utxo in utxos {
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
#[derive(Debug, Clone)]
pub struct TransparentSweepPlan {
    pub input_count: usize,
    pub total_input_zatoshis: u64,
    pub fee_zatoshis: u64,
    /// What actually lands at the destination: inputs minus fee.
    pub output_zatoshis: u64,
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
    use zcash_primitives::transaction::fees::{zip317::FeeRule, FeeRule as _};

    if utxos.is_empty() {
        return Ok(None);
    }

    let total: u64 = utxos.iter().fold(0u64, |acc, u| {
        acc.saturating_add(u64::from(u.txout.value()))
    });

    // Every input is P2PKH — these keys came from `key`/`ckey` records,
    // which store pubkeys, not scripts.
    let input_sizes = utxos
        .iter()
        .map(|utxo| {
            // Every imported key is P2PKH, so every input is standard-sized.
            // Asserted rather than assumed: if a non-P2PKH address ever
            // reaches here the fee is computed for the wrong input size, and
            // while `add_transparent_p2pkh_input` and the runtime fee guard
            // would both catch it, they would catch it as a confusing
            // downstream failure rather than a broken invariant. Raised in
            // review of #187.
            debug_assert!(
                matches!(
                    utxo.address,
                    zcash_transparent::address::TransparentAddress::PublicKeyHash(_)
                ),
                "transparent recovery assumes P2PKH inputs; got {:?}",
                utxo.address
            );
            zcash_primitives::transaction::fees::transparent::InputSize::STANDARD_P2PKH
        })
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
    let fee = u64::from(fee);

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
    use zcash_address::{unified::Container, ConversionError, TryFromAddress, ZcashAddress};

    // Note: the `try_from_sapling` arm below is unreachable through this
    // function. `validate_destination_address` rejects every non-unified
    // address first, so a bare `zs1…` never gets here. Raised in review of
    // #187. Left in place because the arm is required by the trait, but do
    // not "fix" the ordering to reach it — the unified-only rule is what
    // guarantees a destination the sweep can actually pay.
    /// `Found` distinguishes a receiver that is absent from one that is
    /// present but does not decode — reported as the same thing before, so a
    /// user with a corrupt unified address was told to find one with a
    /// Sapling receiver, which theirs already had. Raised in review of #187.
    enum Found {
        Address(sapling::PaymentAddress),
        Malformed,
        Absent,
    }

    struct SaplingOnly(Found);

    impl TryFromAddress for SaplingOnly {
        type Error = &'static str;

        fn try_from_sapling(
            _net: zcash_protocol::consensus::NetworkType,
            data: [u8; 43],
        ) -> Result<Self, ConversionError<Self::Error>> {
            // A present-but-undecodable receiver is not an absent one; see
            // the `MalformedReceiver` handling below.
            Ok(SaplingOnly(
                sapling::PaymentAddress::from_bytes(&data)
                    .map(Found::Address)
                    .unwrap_or(Found::Malformed),
            ))
        }

        fn try_from_unified(
            _net: zcash_protocol::consensus::NetworkType,
            data: zcash_address::unified::Address,
        ) -> Result<Self, ConversionError<Self::Error>> {
            for receiver in data.items() {
                if let zcash_address::unified::Receiver::Sapling(bytes) = receiver {
                    return Ok(SaplingOnly(
                        sapling::PaymentAddress::from_bytes(&bytes)
                            .map(Found::Address)
                            .unwrap_or(Found::Malformed),
                    ));
                }
            }
            Ok(SaplingOnly(Found::Absent))
        }
    }

    let parsed = ZcashAddress::try_from_encoded(destination)
        .map_err(|err| ZeckError::InvalidAddress(format!("could not decode destination: {err}")))?;

    // Reject a destination for the wrong network before anything is signed.
    crate::address::validate_destination_address(destination, network)?;

    let SaplingOnly(receiver) = parsed
        .convert::<SaplingOnly>()
        .map_err(|err| ZeckError::InvalidAddress(format!("unsupported destination: {err}")))?;

    match receiver {
        Found::Address(address) => Ok(address),
        // Present but undecodable. Telling this user to "use a different
        // destination address" would send them hunting for a property their
        // address already has; what they need is a clean copy of it.
        Found::Malformed => Err(ZeckError::MalformedReceiver(
            "this destination carries a Sapling receiver, but its bytes do not decode. \
             The address is damaged rather than the wrong kind — re-copy it from your \
             wallet rather than looking for a different one."
                .to_owned(),
        )),
        Found::Absent => Err(ZeckError::InvalidAddress(
            "this destination has no Sapling receiver. Transparent-only wallet recovery \
             pays into the Sapling pool, so the destination must expose a Sapling \
             receiver; most unified addresses do. Use a different destination address."
                .to_owned(),
        )),
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
    use rand_core::OsRng;
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
        let pubkey = signing_set.add_key(key.secret);
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
            OsRng,
            spend_prover,
            output_prover,
            &fee_rule,
        )
        .map_err(|err| ZeckError::Wallet(format!("building the sweep transaction: {err:?}")))?;

    Ok(result.transaction().clone())
}

/// Outcome of a completed transparent-only sweep.
#[derive(Debug, Clone)]
pub struct TransparentSweepOutcome {
    pub txid: String,
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

/// Sweep every spendable transparent UTXO into one shielded output at
/// `destination`.
///
/// `max_fee_zatoshis` is checked before anything is signed, so a fee the
/// caller considers unacceptable costs nothing.
///
/// Broadcasts. Returns once lightwalletd has accepted the transaction into
/// the mempool — acceptance is not confirmation, and the caller must say so.
pub async fn sweep_transparent_only(
    keys: &[ImportedTransparentKey],
    network: ZeckNetwork,
    lightwalletd_url: &str,
    destination: &str,
    max_fee_zatoshis: Option<u64>,
) -> ZeckResult<Option<TransparentSweepOutcome>> {
    use zcash_client_backend::proto::service::RawTransaction;
    use zcash_proofs::prover::LocalTxProver;
    use zcash_protocol::consensus::BlockHeight;

    // Resolve the destination before touching the network: a bad address
    // should fail instantly, not after a scan.
    let recipient = sapling_receiver(destination, network)?;

    let (mut client, _endpoint, info) =
        crate::lightwalletd::probe_lightwalletd_endpoints_with_retry(lightwalletd_url).await?;
    crate::lightwalletd::validate_lightwalletd_network(network, &info)?;

    let chain_tip = u32::try_from(info.block_height)
        .map_err(|_| ZeckError::Lightwalletd("chain tip height overflowed u32".to_owned()))?;
    let utxos = fetch_transparent_utxos(&mut client, keys, network).await?;

    let params = crate::workspace::consensus_network(network);
    let target_height = BlockHeight::from_u32(chain_tip.saturating_add(1));

    let Some(plan) = plan_sweep(&params, target_height, &utxos)? else {
        return Ok(None);
    };

    if let Some(max_fee) = max_fee_zatoshis {
        if plan.fee_zatoshis > max_fee {
            return Err(ZeckError::InvalidConfig(format!(
                "the sweep needs a {} zatoshi fee for {} input(s), above the {max_fee} \
                 zatoshi limit. Nothing was signed or broadcast.",
                plan.fee_zatoshis, plan.input_count
            )));
        }
    }

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

    let response = client
        .send_transaction(RawTransaction {
            data: raw,
            height: 0,
        })
        .await
        .map_err(|err| ZeckError::Broadcast(err.to_string()))?
        .into_inner();
    if response.error_code != 0 {
        let reason = if response.error_message.is_empty() {
            format!("error code {}", response.error_code)
        } else {
            response.error_message.clone()
        };
        return Err(ZeckError::Broadcast(format!(
            "the node rejected the sweep transaction: {reason}"
        )));
    }

    Ok(Some(TransparentSweepOutcome {
        txid: tx.txid().to_string(),
        plan,
        destination: destination.to_owned(),
    }))
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
    use zcash_protocol::consensus::{BlockHeight, MAIN_NETWORK};

    fn height() -> BlockHeight {
        BlockHeight::from_u32(3_000_000)
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
    fn unified_address_for(network: zcash_protocol::consensus::NetworkType) -> String {
        use zcash_address::unified::{Address, Encoding, Receiver};

        let extsk = sapling_crypto::zip32::ExtendedSpendingKey::master(&[0x7u8; 32]);
        let (_, payment_address) = extsk.default_address();

        let ua = Address::try_from_items(vec![Receiver::Sapling(payment_address.to_bytes())])
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
        let err = match sapling_receiver("t1UE73p3WKJRqjMTyFqRKXieX9FkWTNvZhm", ZeckNetwork::Testnet)
        {
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
