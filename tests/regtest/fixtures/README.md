# Golden wallet.dat fixtures

Real `wallet.dat` files written by a pinned `zcashd`, used to test the
Berkeley DB parser in `crates/argos-wallet-import`.

They exist because a test-only wallet *writer* validated against our own
reader is a self-consistent misreading that passes every test. These files
are written by the real producer, so they are the only ground truth
available — especially for `czkey`, which nothing else in the ecosystem
decrypts and which therefore has no reference implementation to check
against.

## Regenerating

Not part of the regtest stack; the service sits behind a compose profile so
it never starts with Zebra and lightwalletd.

    cd tests/regtest
    docker compose --profile fixtures up --abort-on-container-exit zcashd-fixtures
    cp fixtures/out/*.dat ../../crates/argos-wallet-import/tests/fixtures/

`fixtures/out/` is git-ignored. The committed copies under
`crates/argos-wallet-import/tests/fixtures/` are what the tests read.

## Why two chain configurations

`zcashd` refuses to create Sprout addresses once Canopy is active
(`src/wallet/rpcwallet.cpp:3236` in v6.20.0), and regtest activation
heights are configurable — so Canopy is held inactive for the Sprout
wallets and activated at height 1 for the rest.

Consensus branch IDs, from `src/consensus/upgrades.cpp` at v6.20.0:

| Upgrade | Branch ID |
|---|---|
| Overwinter | `5ba81b19` |
| Sapling | `76b809bb` |
| Blossom | `2bb40e60` |
| Heartwood | `f5b9230b` |
| **Canopy** | **`e9ff75a6`** |

Canopy is the only one that matters here. Getting it wrong silently
produces fixtures with no Sprout keys at all.

`encryptwallet` is additionally gated on `fExperimentalDeveloperEncryptWallet`
(`src/wallet/rpcwallet.cpp:2329`), so the config sets both
`experimentalfeatures=1` and `developerencryptwallet=1`.

## The fixtures

Passphrase for every encrypted wallet: `argos-test-passphrase`

| File | Canopy | Contains |
|---|---|---|
| `sprout-plaintext.dat` | inactive | plaintext `zkey`, `sapzkey`, transparent `key` |
| `sprout-encrypted.dat` | inactive | **`czkey`**, `mkey`, `csapzkey`, `ckey` |
| `modern-plaintext.dat` | active | `sapzkey`, transparent `key`; no Sprout |
| `modern-encrypted.dat` | active | `mkey`, `csapzkey`, `ckey`; no Sprout |
| `*-truncated.dat` | — | each golden cut to 60% of its length |

Verified record counts at generation time:

| File | `czkey` | `mkey` | bare `zkey` |
|---|---|---|---|
| `sprout-plaintext` | 0 | 0 | 1 |
| `sprout-encrypted` | 1 | 1 | **0** |
| `modern-plaintext` | 0 | 0 | 0 |
| `modern-encrypted` | 0 | 1 | 0 |

The `sprout-encrypted` row is the important one: `czkey` appears and the
bare `zkey` is gone, which is `walletdb.cpp:125` writing the encrypted
record and erasing the plaintext one.

## Do not

- Weaken the record-count checks to make a run pass. A `sprout-encrypted.dat`
  without a `czkey` record is worthless — every downstream test would be
  validating nothing.
- Hand-construct these files. The point is that zcashd wrote them.
