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

use zcash_client_backend::proto::service::{
    compact_tx_streamer_client::CompactTxStreamerClient, GetAddressUtxosArg,
};
use zcash_transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
};
use zcash_protocol::value::Zatoshis;
use tonic::transport::Channel;
use tracing::warn;

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
            let value = match u64::try_from(entry.value_zat).ok().and_then(|v| {
                Zatoshis::from_u64(v).ok()
            }) {
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
        .map(|(address, (zatoshis, utxo_count))| TransparentAddressBalance {
            address: encode_transparent_address(&address, network),
            zatoshis,
            utxo_count,
        })
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

    let total: u64 = utxos
        .iter()
        .fold(0u64, |acc, u| acc.saturating_add(u64::from(u.txout.value())));

    // Every input is P2PKH — these keys came from `key`/`ckey` records,
    // which store pubkeys, not scripts.
    let input_sizes = utxos
        .iter()
        .map(|_| zcash_primitives::transaction::fees::transparent::InputSize::STANDARD_P2PKH)
        .collect::<Vec<_>>();

    let fee = FeeRule::standard()
        .fee_required(
            params,
            target_height,
            input_sizes,
            // No transparent outputs: the single output is shielded.
            std::iter::empty(),
            0,
            1,
            0,
            0,
        )
        .map_err(|err| ZeckError::Wallet(format!("computing the ZIP-317 fee failed: {err:?}")))?;
    let fee = u64::from(fee);

    let Some(output) = total.checked_sub(fee).filter(|out| *out > 0) else {
        return Err(ZeckError::InvalidConfig(format!(
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
        let utxos = vec![
            utxo(addr(1), 500_000, 0xAA),
            utxo(addr(2), 250_000, 0xBB),
        ];
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
        let many: Vec<_> = (0u8..40)
            .map(|i| utxo(addr(i), 10_000_000, i))
            .collect();

        let small = plan_sweep(&MAIN_NETWORK, height(), &few)
            .unwrap()
            .unwrap();
        let large = plan_sweep(&MAIN_NETWORK, height(), &many)
            .unwrap()
            .unwrap();

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
