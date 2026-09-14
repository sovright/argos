# Address discovery and recovery

Use **Find this address** when you know an address but do not know which of
up to 64 candidate seed phrases generated it. Matching runs locally without
network requests. It checks every candidate in the selected ranges, even
when preceding addresses have no activity; there is no unused-address gap
stop. This is address discovery, not a balance scan.

## Supported derivations

| Target | Derivation | Search coordinates |
| --- | --- | --- |
| Transparent P2PKH (`t1` on mainnet) | BIP44 `m/44'/coin_type'/account'/branch/index` | Account, external/internal branch, child index |
| Sapling (`zs`) | ZIP32 Sapling `m/32'/coin_type'/account'` | Account and external diversifier index |
| Unified (`u`) | Decode receivers and check each supported pool independently | Transparent, Sapling, and/or Orchard coordinates |
| Orchard receiver inside a UA | ZIP32 Orchard `m/32'/coin_type'/account'` | Account, external/internal scope, diversifier index |

Mainnet coin type is 133; testnet is 1. The **ZecWallet Lite** preset fixes
transparent account 0. The GUI defaults to receive indices 0–999, with a
configurable start and count. Change/internal scanning is off by default.
Other accounts and change scanning are available under **Advanced**. The
**Advanced BIP44 accounts** profile enables other transparent
accounts; shielded derivation remains ZIP32. A profile is a search scope, not
an assertion that a particular wallet generated the target.

Shielded scopes are not BIP44 change levels. The current matcher searches
external Sapling addresses and external/internal Orchard addresses. It skips
invalid Sapling diversifiers without advancing them to a different index.
Sapling internal address discovery is excluded from this implementation.

Search coordinates are limited to 0 through 2,147,483,647. This is an Argos
implementation bound, not the shielded diversifier space: both Sapling and
Orchard have 88-bit diversifier indices. Searches are limited to 10 million
seed/account/scope/index candidates and 256 receiver matches per job. Split
larger searches into ranges. A no-match result rules out only the requested
range, derivation schemes, and supplied mnemonic/passphrase combinations.

## Passphrases and unsupported inputs

The optional **BIP39 passphrase** participates in mnemonic-to-seed derivation.
It is separate from a wallet-file encryption password. Leaving it empty
preserves ordinary ZecWallet Lite seed derivation. Every different passphrase
produces a different seed; Argos cannot detect a mistyped passphrase from the
mnemonic checksum. Supply known candidate combinations explicitly.

This matcher does not search random imported private keys, P2SH scripts
(`t3` on mainnet), Sprout addresses, arbitrary historical wallet schemes,
legacy zcashd emergency phrase interpretations, or the full shielded
diversifier space. Imported wallet/key recovery remains a separate flow.

A Unified Address result identifies the matching receiver and pool. It does
**not** establish ownership of the other bundled receivers. The match may be
rendered as a bare Sapling address or an Orchard-only UA, rather than the
original combined UA string.

## Recovery and resume

**Recover this match** carries an opaque match identifier to the recovery
configuration screen. A transparent match imports only the exact derived
private key into the existing transparent UTXO recovery flow. A Sapling match
imports its account spending key. An Orchard match scans exactly the matched
HD account, including other receivers in that account through the existing
HD scanner. Shielded recovery is account-level, not restricted to one
diversifier. Network settings and an appropriate birthday are required before
starting recovery; discovery itself never connects to a server.

The backend re-derives and verifies the address before creating the recovery
key source. Session metadata stores public account/scope/index/address/path
coordinates. Resuming requires re-entering the seed and, when used, the same
BIP39 passphrase; both the address and workspace fingerprint are verified.
Search requests and recovery metadata do not serialize seed bytes or
passphrases. GUI inputs clear after submission. Retained backend search keys
are released after cancellation or successful handoff. JavaScript strings
cannot provide a guaranteed memory-zeroization boundary.

## Sources

- [ZecWallet Lite address creation](https://github.com/adityapk00/zecwallet-light-cli/blob/fd5d11f0f28e0f1628ea8fdad0cce16d50e6bb98/lib/src/lightwallet/keys.rs)
- [ZecWallet Lite transparent derivation](https://github.com/adityapk00/zecwallet-light-cli/blob/fd5d11f0f28e0f1628ea8fdad0cce16d50e6bb98/lib/src/lightwallet/wallettkey.rs)
- [ZIP32: shielded hierarchical deterministic wallets](https://github.com/zcash/zips/blob/main/zips/zip-0032.rst)
- [BIP44 account and change structure](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
- [BIP39 mnemonic and optional passphrase](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)

Tests use public synthetic seeds. They establish derivation, handoff, and
lifecycle behavior; they do not establish funded mainnet recovery or broadcast
success. Native GUI and funded-chain testing should be completed before a
release claim.
