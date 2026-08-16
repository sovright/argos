#!/usr/bin/env bash
# Generate golden wallet.dat fixtures with the real producer.
#
# Two chain configs are needed. zcashd refuses to create Sprout addresses
# once Canopy is active:
#
#   src/wallet/rpcwallet.cpp:3236
#     if (addrType == ADDR_TYPE_SPROUT) {
#         if (... NetworkUpgradeActive(chainActive.Height(), UPGRADE_CANOPY)) {
#             throw JSONRPCError(RPC_INVALID_PARAMETER, ...);
#
# On regtest the activation heights are configurable, so we hold Canopy
# inactive for the Sprout wallets and activate everything for the rest.
set -euo pipefail

PASSPHRASE="argos-test-passphrase"
OUT=/fixtures

gen_wallet() {
  local name="$1" canopy_height="$2" encrypt="$3" sprout="$4"

  local datadir="/tmp/zc-$name"
  rm -rf "$datadir"; mkdir -p "$datadir"

  # Consensus branch IDs, verified against zcash/zcash v6.20.0
  # src/consensus/upgrades.cpp:
  #   5ba81b19 Overwinter   76b809bb Sapling   2bb40e60 Blossom
  #   f5b9230b Heartwood    e9ff75a6 Canopy
  #
  # Canopy (e9ff75a6) is the one that matters: z_getnewaddress sprout
  # throws once it is active. Everything below it is activated at height 1
  # so the chain is otherwise modern.
  cat > "$datadir/zcash.conf" <<EOF
i-am-aware-zcashd-will-be-replaced-by-zebrad-and-zallet-in-2025=1
allowdeprecated=getnewaddress
allowdeprecated=getrawchangeaddress
allowdeprecated=z_getnewaddress
allowdeprecated=z_getbalance
allowdeprecated=z_gettotalbalance
allowdeprecated=z_listaddresses
allowdeprecated=legacy_privacy
regtest=1
nuparams=5ba81b19:1
nuparams=76b809bb:1
nuparams=2bb40e60:1
nuparams=f5b9230b:1
nuparams=e9ff75a6:${canopy_height}
rpcuser=fixture
rpcpassword=fixture
# encryptwallet is gated on fExperimentalDeveloperEncryptWallet
# (zcash/zcash v6.20.0 src/wallet/rpcwallet.cpp:2329), which is set by
# -developerencryptwallet and itself requires -experimentalfeatures.
# Both live in the config file rather than the command line so they
# cannot be dropped by a wrapper entrypoint.
experimentalfeatures=1
developerencryptwallet=1
EOF

  zcashd -datadir="$datadir" -daemon
  for i in $(seq 1 60); do
    zcash-cli -datadir="$datadir" getblockcount >/dev/null 2>&1 && break
    if [ "$i" = 60 ]; then
      echo "zcashd for $name failed to come up within 60s" >&2
      exit 1
    fi
    sleep 1
  done

  # Sprout generation is also blocked during initial block download.
  zcash-cli -datadir="$datadir" generate 3 >/dev/null

  zcash-cli -datadir="$datadir" getnewaddress >/dev/null
  zcash-cli -datadir="$datadir" z_getnewaddress sapling >/dev/null

  if [ "$sprout" = "yes" ]; then
    zcash-cli -datadir="$datadir" z_getnewaddress sprout >/dev/null
  fi

  if [ "$encrypt" = "yes" ]; then
    # encryptwallet rewrites zkey -> czkey and writes mkey, then stops the node.
    #
    # This must NOT be tolerated with `|| true`. A swallowed failure here
    # produces a file named "*-encrypted.dat" that contains plaintext zkey
    # records and no czkey at all — the exact silent failure that would
    # make every downstream czkey test validate nothing.
    if ! zcash-cli -datadir="$datadir" encryptwallet "$PASSPHRASE"; then
      echo "FATAL: encryptwallet failed for $name — refusing to write a" >&2
      echo "fixture that claims to be encrypted but is not." >&2
      exit 1
    fi
    sleep 3
  fi

  # Unconditional: encryptwallet stops the node on success, but on failure
  # (or for the plaintext case) it is still running and must be stopped
  # explicitly — otherwise it keeps holding the RPC port and the next
  # gen_wallet call's zcash-cli talks to the wrong node.
  zcash-cli -datadir="$datadir" stop >/dev/null 2>&1 || true
  stopped=no
  for i in $(seq 1 30); do
    if ! zcash-cli -datadir="$datadir" getblockcount >/dev/null 2>&1; then
      stopped=yes
      break
    fi
    sleep 1
  done
  # Copying a wallet.dat out from under a live zcashd yields a file with a
  # torn BDB page or a stale record set — which looks like a parser bug
  # later, not a fixture bug. Fail here instead of shipping one.
  if [ "$stopped" != yes ]; then
    echo "FATAL: zcashd for $name did not stop within 30s; refusing to copy a" >&2
    echo "wallet.dat that is still being written." >&2
    exit 1
  fi
  sleep 1

  cp "$datadir/regtest/wallet.dat" "$OUT/$name.dat"
  echo "wrote $OUT/$name.dat"
}

mkdir -p "$OUT"
# Idempotent: a partial previous run leaves .dat files behind, and the
# truncation loop below would then truncate its own earlier output into
# "*-truncated-truncated.dat".
rm -f "$OUT"/*.dat

# Canopy at height 9_999_999 == never active on a 3-block chain.
gen_wallet sprout-plaintext   9999999 no  yes
gen_wallet sprout-encrypted   9999999 yes yes
gen_wallet modern-plaintext   1       no  no
gen_wallet modern-encrypted   1       yes no

# Corruption variants: truncate each golden to 60% of its length.
#
# Iterate the known golden names rather than globbing *.dat — the loop
# writes into the directory it would otherwise be globbing, which is how
# "*-truncated-truncated.dat" gets created.
for base in sprout-plaintext sprout-encrypted modern-plaintext modern-encrypted; do
  size=$(stat -c%s "$OUT/$base.dat")
  head -c $((size * 60 / 100)) "$OUT/$base.dat" > "$OUT/${base}-truncated.dat"
done

echo "fixture generation complete"
