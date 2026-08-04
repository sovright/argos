#!/usr/bin/env bash
# Argos regtest harness — initial-funding script.
#
# Run AFTER `docker compose up -d` has the stack up. Funds the well-known
# Argos test seed so the C2 integration tests have a known-funded wallet to
# recover, and mines past coinbase maturity so those funds are spendable.
#
# Exits non-zero on any failure. Re-running tops the seed up with additional
# notes rather than resetting anything — but note that on an already-mined
# chain those notes are worth nothing, because the regtest subsidy has decayed
# by then. Recovering a chain whose addresses have been swept means
# `docker compose down -v` and a full rebuild.
#
# ── What changed, and why ──────────────────────────────────────────────────
#
# The node used to be zcashd and this script funded the seed with
# `zcash-cli sendtoaddress`. Neither is available any more:
#
#   * zcashd has no Ironwood. `UPGRADE_NU6_3` appears nowhere in zcash/zcash,
#     not in v6.20.0 nor on master, so a zcashd chain can never activate
#     NU6.3 and the post-activation sweep path is untestable on it.
#
#   * Zebra has no wallet at all — no `sendtoaddress`, no `getnewaddress`.
#
# Funding therefore runs through the `argos-regtest-funder` helper, which
# mines *shielded* coinbase (ZIP 213) straight to the seed. Transparent
# coinbase would not work: spending it needs `CoinbaseFilter::CoinbaseOnly`,
# which only selects outputs the wallet knows are coinbase, and that knowledge
# is the transaction's index within its block. `GetAddressUtxos` does not
# report that index, so a lightwalletd-backed wallet can never establish it.
#
# Consequence worth knowing: the test seed ends up holding SHIELDED funds, not
# the transparent UTXOs the older network-resilience tests were written
# against. See README.md.
#
# Prerequisites:
#   - `docker compose up -d` running in this directory.
#   - A Rust toolchain; the funder helper is built on demand.
#
# Environment overrides:
#   REGTEST_ZEBRA_RPC_URL      Zebra JSON-RPC endpoint
#                              (default http://127.0.0.1:18232).
#   REGTEST_ZEBRA_CONTAINER    Container name (default argos-zebrad-regtest).
#   REGTEST_FUND_BLOCKS        Coinbase blocks paid to the seed (default 4).
#                              Each block is one spendable note, so >1 makes a
#                              sweep select across notes.
#   REGTEST_FUND_SEED          Mnemonic to fund (default: the Argos test seed).

set -euo pipefail

readonly ZEBRA_RPC_URL="${REGTEST_ZEBRA_RPC_URL:-http://127.0.0.1:18232}"
readonly ZEBRA_CONTAINER="${REGTEST_ZEBRA_CONTAINER:-argos-zebrad-regtest}"
readonly FUND_BLOCKS="${REGTEST_FUND_BLOCKS:-4}"
# Argos test seed (BIP-39 test vector — no real funds anywhere). Documented
# in CLAUDE.md as the only seed safe to commit anywhere.
readonly ARGOS_TEST_SEED="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
readonly FUND_SEED="${REGTEST_FUND_SEED:-$ARGOS_TEST_SEED}"

# The treasury. A separate seed from the one under test, deliberately: sweep
# tests drain the wallets they test, and a treasury that could be drained
# would defeat the point of having one. Another BIP-39 test vector, no real
# funds anywhere.
readonly TREASURY_SEED="${REGTEST_TREASURY_SEED:-zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote}"
# Coinbase blocks paid to the treasury near genesis. At ~6.25 ZEC each this is
# far more than the suite spends, which is the intent: topping the treasury up
# later is impossible, so it is filled once with plenty of headroom.
readonly TREASURY_BLOCKS="${REGTEST_TREASURY_BLOCKS:-30}"
# Paid to each test address per run. 12.5 ZEC.
readonly FUND_ZATOSHIS="${REGTEST_FUND_ZATOSHIS:-1250000000}"
readonly LIGHTWALLETD_URL="${REGTEST_LIGHTWALLETD_URL:-http://localhost:9067}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly REPO_ROOT

log() { printf '[regtest-setup] %s\n' "$*"; }
die() { printf '[regtest-setup] ERROR: %s\n' "$*" >&2; exit 1; }

# Zebra runs with `enable_cookie_auth = false` (see zebrad-regtest.toml), so
# no credentials are needed. The port is loopback-only.
zrpc() {
    local method="$1" params="${2:-[]}"
    curl -s --max-time 120 -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"${method}\",\"params\":${params}}" \
        "$ZEBRA_RPC_URL"
}

# ── Prerequisites ───────────────────────────────────────────────────────────

command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
command -v curl   >/dev/null 2>&1 || die "curl not found on PATH"
command -v cargo  >/dev/null 2>&1 || die "cargo not found on PATH"

docker ps --format '{{.Names}}' | grep -qx "$ZEBRA_CONTAINER" \
    || die "container $ZEBRA_CONTAINER is not running — run 'docker compose up -d' first"

# ── Wait for RPC readiness ─────────────────────────────────────────────────

log "waiting for Zebra RPC at $ZEBRA_RPC_URL ..."
for _ in $(seq 1 60); do
    if zrpc getblockchaininfo | grep -q '"result"'; then
        log "RPC ready"
        break
    fi
    sleep 2
done
zrpc getblockchaininfo | grep -q '"result"' \
    || die "Zebra RPC never came up — check 'docker compose logs zebrad-regtest'"

# Guard the assumption the whole harness rests on. If Ironwood is not active
# the sweep test silently degrades into testing a pre-NU6.3 branch, which is
# exactly the bug this harness exists to catch.
zrpc getblockchaininfo | grep -q '"NU6.3"' \
    || die "Zebra does not report an NU6.3 upgrade — check the activation heights in zebrad-regtest.toml"
log "Ironwood (NU6.3) present in the chain's upgrade set"

# ── Build the funding helper ───────────────────────────────────────────────

log "building argos-regtest-funder ..."
( cd "$REPO_ROOT" && cargo build -q -p argos-core --features argos-network --bin argos-regtest-funder ) \
    || die "failed to build argos-regtest-funder"
FUNDER="$REPO_ROOT/target/debug/argos-regtest-funder"
readonly FUNDER
[ -x "$FUNDER" ] || die "funder binary missing at $FUNDER"

# ── Fund the treasury ──────────────────────────────────────────────────────
#
# Only the treasury is paid with coinbase, and only here, near genesis. The
# regtest subsidy halves every ~150 blocks and is worth nothing past about
# height 6,000, so this is the one window in which mining pays anything.
#
# Everything else is funded from the treasury by ordinary shielded transfer
# after the mining below, because a transfer does not care what the subsidy is
# doing. That is what makes this script re-runnable: a suite run that drains a
# swept address is recovered by running setup.sh again, not by rebuilding the
# chain from genesis.
#
# (Zebra cannot fix the subsidy from config — `pre_blossom_halving_interval`
# is accepted on Regtest and ignored. See zebrad-regtest.toml.)
log "funding the treasury with $TREASURY_BLOCKS shielded coinbase block(s) ..."
ARGOS_REGTEST_FUND_SEED="$TREASURY_SEED" "$FUNDER" \
    --zebra-rpc-url "$ZEBRA_RPC_URL" \
    --blocks "$TREASURY_BLOCKS" \
    || die "funding the treasury failed"

# ── Mine past the ZIP 212 grace period ─────────────────────────────────────
#
# PCZT construction requires ZIP 212 to be fully enforced for outputs, which
# only begins ZIP212_GRACE_PERIOD (32,256) blocks after Canopy activation.
# Regtest activates Canopy at height 1, so nothing built through the PCZT
# roles works below height 32,257 — see README.md.
ZIP212_HEIGHT=32400
log "mining to height $ZIP212_HEIGHT for ZIP 212 enforcement (needed by the PCZT tests) ..."
while :; do
    height="$(zrpc getblockcount | sed -e 's/.*"result":\([0-9]*\).*/\1/')"
    [ "$height" -ge "$ZIP212_HEIGHT" ] && break
    zrpc generate '[500]' >/dev/null 2>&1 || sleep 2
done

# ── Clear Zebra's gossip backlog ───────────────────────────────────────────
#
# Zebra queues each mined block for gossip to its peers. A regtest node is
# isolated, so nothing drains that queue, and tens of thousands of blocks
# fill it. Every later `generate` then fails with "failed to send mined
# block to gossip task: no available capacity" — while still accepting the
# block, so the height advances and only the RPC reports failure. Tests that
# fund themselves die on that error immediately after a successful setup.
#
# A restart empties the queue. Do it here so the harness is handed over in a
# usable state rather than failing on the user's first test run.
log "restarting Zebra to clear the gossip queue left by bulk mining ..."
docker restart "$ZEBRA_CONTAINER" >/dev/null 2>&1 \
    || die "could not restart $ZEBRA_CONTAINER"
for _ in $(seq 1 60); do
    zrpc getblockcount 2>/dev/null | grep -q result && break
    sleep 2
done
zrpc getblockcount 2>/dev/null | grep -q result \
    || die "Zebra did not come back after the restart"

# ── Fund every test address from the treasury ──────────────────────────────
#
# One transaction for all of them. Funding them one at a time would need a
# mined block and a treasury rescan between each, so the next payment could
# see the previous one's change note — minutes per address against a
# 32,000-block chain.
log "deriving the addresses to fund ..."
FIXTURE_JSON="$("$FUNDER" --zebra-rpc-url "$ZEBRA_RPC_URL" --print-fixture-addresses)" \
    || die "could not read the fixture addresses"
FIXTURE_SAPLING="$(printf '%s' "$FIXTURE_JSON" | sed -e 's/.*"sapling":"\([^"]*\)".*/\1/')"
FIXTURE_TRANSPARENT="$(printf '%s' "$FIXTURE_JSON" | sed -e 's/.*"transparent":"\([^"]*\)",.*/\1/')"
STANDALONE_TRANSPARENT="$(printf '%s' "$FIXTURE_JSON" \
    | sed -e 's/.*"standalone_transparent":"\([^"]*\)".*/\1/')"
[ -n "$FIXTURE_SAPLING" ] || die "could not parse the fixture Sapling address"
[ -n "$FIXTURE_TRANSPARENT" ] || die "could not parse the fixture transparent address"
[ -n "$STANDALONE_TRANSPARENT" ] || die "could not parse the standalone transparent address"

seed_address() {
    ARGOS_REGTEST_FUND_SEED="$FUND_SEED" "$FUNDER" \
        --zebra-rpc-url "$ZEBRA_RPC_URL" \
        --account "$1" --print-address-only \
        | sed -e 's/.*"address":"\([^"]*\)".*/\1/'
}
# Account 1 as well as account 0: R-S29 kills a sweep between two per-account
# broadcasts and asserts the resumed run produces exactly one. With a single
# funded account there is only ever one broadcast and the property cannot exist.
SEED_ACCOUNT_0="$(seed_address 0)"
SEED_ACCOUNT_1="$(seed_address 1)"
[ -n "$SEED_ACCOUNT_0" ] || die "could not derive the test seed's account 0 address"
[ -n "$SEED_ACCOUNT_1" ] || die "could not derive the test seed's account 1 address"

log "funding every test address from the treasury in one transaction ..."
ARGOS_REGTEST_FUND_SEED="$TREASURY_SEED" "$FUNDER" \
    --zebra-rpc-url "$ZEBRA_RPC_URL" \
    --lightwalletd-url "$LIGHTWALLETD_URL" \
    --transfer "$SEED_ACCOUNT_0:$FUND_ZATOSHIS" \
    --transfer "$SEED_ACCOUNT_1:$FUND_ZATOSHIS" \
    --transfer "$FIXTURE_SAPLING:$FUND_ZATOSHIS" \
    --transfer "$FIXTURE_TRANSPARENT:$FUND_ZATOSHIS" \
    --transfer "$STANDALONE_TRANSPARENT:$FUND_ZATOSHIS" \
    || die "treasury funding transfer failed"

# Confirm the funding transaction. Transfers are ordinary transactions, so
# they need one block, not the 100 a coinbase output needs.
zrpc generate '[2]' >/dev/null 2>&1 || true

HEIGHT="$(zrpc getblockcount | sed -e 's/.*"result":\([0-9]*\).*/\1/')"
readonly HEIGHT
log "done — chain height $HEIGHT"
log ""
log "Next:"
log "    export ARGOS_REGTEST_LIGHTWALLETD_URL=http://localhost:9067"
# R-S29 reads this as a gate: its value is not used, its presence signals
# that account 1 was funded by a setup.sh new enough to do so.
log "    export ARGOS_REGTEST_TEST_T_ADDR_1=funded"
log "    cargo test -p argos-core --features argos-network -- --ignored"
