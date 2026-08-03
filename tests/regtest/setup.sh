#!/usr/bin/env bash
# Argos regtest harness — initial-funding script.
#
# Run AFTER `docker compose up -d` has the stack up. Funds the well-known
# Argos test seed so the C2 integration tests have a known-funded wallet to
# recover, and mines past coinbase maturity so those funds are spendable.
#
# Exits non-zero on any failure. Re-running is safe: it tops the seed up with
# additional notes rather than resetting anything. For a clean chain, run
# `docker compose down -v` first.
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

# ── Fund ───────────────────────────────────────────────────────────────────

log "funding the test seed with $FUND_BLOCKS shielded coinbase block(s), then mining to maturity ..."
ARGOS_REGTEST_FUND_SEED="$FUND_SEED" "$FUNDER" \
    --zebra-rpc-url "$ZEBRA_RPC_URL" \
    --blocks "$FUND_BLOCKS" \
    || die "funding failed"

# ── Fund the imported-wallet tests ─────────────────────────────────────────
#
# These spend from the golden wallet.dat fixture, so they need that exact
# file's addresses funded — no other address leaves them anything to find.
#
# Funding MUST happen here, before the ZIP 212 mining below. The regtest
# block subsidy halves every ~150 blocks and is worthless past about height
# 6,000, while ZIP 212 enforcement does not begin until 32,257. Mining first
# and funding afterwards produces coinbase worth nothing, which surfaces as
# "a funded wallet must report a non-zero balance" — a funding failure that
# reads like a scanning bug.
log "funding the imported-wallet fixture addresses ..."
FIXTURE_JSON="$("$FUNDER" --zebra-rpc-url "$ZEBRA_RPC_URL" --print-fixture-addresses)" \
    || die "could not read the fixture addresses"
FIXTURE_SAPLING="$(printf '%s' "$FIXTURE_JSON" | sed -e 's/.*"sapling":"\([^"]*\)".*/\1/')"
FIXTURE_TRANSPARENT="$(printf '%s' "$FIXTURE_JSON" | sed -e 's/.*"transparent":"\([^"]*\)".*/\1/')"
[ -n "$FIXTURE_SAPLING" ] || die "could not parse the fixture Sapling address"
[ -n "$FIXTURE_TRANSPARENT" ] || die "could not parse the fixture transparent address"

for addr in "$FIXTURE_SAPLING" "$FIXTURE_TRANSPARENT"; do
    ARGOS_REGTEST_FUND_SEED="$FUND_SEED" "$FUNDER" \
        --zebra-rpc-url "$ZEBRA_RPC_URL" \
        --address "$addr" \
        --blocks "$FUND_BLOCKS" \
        || die "funding $addr failed"
done

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

HEIGHT="$(zrpc getblockcount | sed -e 's/.*"result":\([0-9]*\).*/\1/')"
readonly HEIGHT
log "done — chain height $HEIGHT"
log ""
log "Next:"
log "    export ARGOS_REGTEST_LIGHTWALLETD_URL=http://localhost:9067"
log "    cargo test -p argos-core --features argos-network -- --ignored"
