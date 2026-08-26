# wallet.dat import — design

**Date:** 2026-07-30
**Status:** implemented on `main`; retained as the original design record
**Scope:** sub-spec 1 of 3 (see [Project decomposition](#project-decomposition))

## Problem

Argos recovers ZecWallet Lite wallets from a BIP-39 seed. It cannot read a
wallet *file*, so three classes of funds are out of reach:

1. **zcashd wallets** whose keys were imported (`z_importkey`) rather than
   HD-derived, and therefore appear in no seed.
2. **Sprout funds**, whose spending keys were never HD-derived at all.
3. **ZecWallet Lite wallet files**, for users who have the file but not the seed
   phrase.

`README.md:46` and `docs/THREAT_MODEL.md:374` currently state that Sprout
recovery is impossible in Argos. This project reverses that.

### Why this is urgent

The ecosystem's official migration path abandons Sprout. Zallet's
`migrate-zcashd-wallet` reports Sprout spending keys as unmigratable and
instructs users to "move any Sprout funds using `zcashd` before migrating".
`zcash/zewif-zcashd` extracts unencrypted Sprout keys but returns an explicit
error for **encrypted** Sprout spending keys (`czkey`), noting Sprout "has been
deprecated since 2018".

zcashd is end-of-life and cannot follow the chain past Ironwood (NU6.3), so
"move your funds using zcashd first" is unfollowable advice for anyone who did
not act in time.

**A user with an encrypted zcashd wallet containing Sprout funds currently has
no recovery path in any software.** That gap is the sharpest statement of what
this project is for.

## Project decomposition

The request covers three subsystems. Build order is forced by dependency, not
preference.

| # | Sub-spec | Depends on | Character |
|---|---|---|---|
| 1 | **wallet.dat ingestion** (this document) | nothing | Bounded engineering. Feeds all downstream work. |
| 2 | **Sapling→Ironwood migration** | (1) optionally; works seed-only | Smallest. Existing sweep machinery plus `ShieldedPool::Ironwood`, already regtest-proven at `crates/zeck-core/tests/regtest_integration.rs:2345`. |
| 3 | **Sprout recovery** | (1) for keys, plus a new data source | Research. Cannot ride on lightwalletd. |

Sub-specs 2 and 3 get their own brainstorm → spec → plan cycles.

### Constraints discovered for sub-spec 3

Recorded here so they are not rediscovered later.

- **JoinSplit proving exists.** `zcash_proofs-0.30.0/src/sprout.rs:19` ships
  `create_proof`, with the full circuit at `src/circuit/sprout/mod.rs`.
- **The transaction builder refuses to construct Sprout bundles.**
  `zcash_primitives-0.30.0/src/transaction/builder.rs:1570`:
  `// We don't support constructing Sprout bundles.` A v4 transaction with a
  hand-assembled JoinSplit bundle is buildable — `JsDescription::read`/`write`
  exist at `src/transaction/components/sprout.rs:89,168`, and `sighash_v4` is
  present — but entirely outside the builder. That is Argos-side code.
- **lightwalletd cannot see Sprout at all.** `CompactBlock`/`CompactTx` carry no
  Sprout fields, and `TreeState` (`crates/zeck-core/tests/proto/service.proto:97`)
  exposes exactly `saplingTree` and `orchardTree` — no `sproutTree`. There is no
  way over Argos's current transport to discover Sprout notes, obtain a witness,
  or obtain an anchor.
- **Decision: Argos maintains its own Sprout index and commitment tree.**
- **Open:** that still requires a full-block source. lightwalletd's
  `GetTransaction` fetches by txid but cannot enumerate, so the source resolves
  to a Zebra `getblock` endpoint or an explorer API. The decision made was about
  *who owns the tree* (us), not about escaping the transport problem.
- **Mitigating discovery:** wallet.dat already caches `SproutNoteData` and
  `SproutWitness` (29-level tree). If those cached witnesses are usable, the cost
  of building an index from genesis may collapse. Sub-spec 1 therefore preserves
  them (see [`ImportedKeys`](#components)).

### A Sprout sweep is necessarily two transactions

Sprout funds cannot move directly to Ironwood. This is not a policy choice or a
turnstile rule that might be relaxed — it is unrepresentable in the transaction
format. From `zcash_primitives-0.30.0/src/transaction/mod.rs:142,156,166,175`:

| Tx version | Sprout | Sapling | Orchard | Ironwood |
|---|---|---|---|---|
| V4 | yes | yes | no | no |
| V5 | no | yes | yes | no |
| V6 | no | yes | yes | yes |

Sprout requires a V4 transaction. Ironwood requires V6. **Sapling is the only
pool present in both**, so it is the mandatory intermediate:

```
Sprout ──(V4 tx: JoinSplit + Sapling output)──► Sapling ──(V6 tx)──► Ironwood
```

Consequences that sub-spec 3 must design for, not discover:

1. **Two broadcasts, not one.** The sweep has an intermediate state in which the
   user's funds sit in Sapling. That state must be durable and resumable: if
   Argos dies between the two transactions the user must be able to restart and
   complete the second hop, not be left believing the sweep failed.
2. **The destination UA must contain a Sapling receiver.** Argos currently
   accepts any destination with "an Orchard or Sapling receiver"
   (`ZeckError::DestinationMissingShieldedReceiver`). For a sweep containing
   Sprout funds, an Orchard-only destination is unusable — the first hop has
   nowhere to land. This needs a distinct validation and a distinct error.
3. **Fees are paid twice**, and the `--max-fee` check must account for both hops
   before broadcasting the first, or a user can be stranded mid-migration with a
   fee cap that stops the second.
4. **The Sapling hop is a visible turnstile crossing.** Value entering and
   leaving the Sapling pool is public even though the addresses are not. This
   belongs in the threat model's privacy discussion for sub-spec 3.
5. **V4 transactions remain accepted after Ironwood** (confirmed by Zaki,
   2026-07-30). This was the question gating the entire sub-spec: Sprout exists
   only in V4, so if a future upgrade stopped accepting that version, Sprout
   would become permanently unspendable by anyone and no amount of key recovery
   would help. It does not, so the recovery path is real.

### Sprout is a closed pool, but not a sealed one

Two findings taken together describe the situation precisely, and they point in
opposite directions:

- **Nothing can enter Sprout.** zcashd refuses all inbound transfers —
  `z_sendmany` to a Sprout address fails with *"Sending funds into the Sprout
  pool is no longer supported"*, independent of the configured Canopy
  activation height. Established by attempting exactly that while generating
  test fixtures; see `tests/regtest/fixtures/README.md`.
- **Value can still leave**, because V4 is still accepted.

So every Sprout note in existence predates November 2020, the set is closed and
shrinking, and the funds are recoverable — but only by software that can build
a V4 transaction with a JoinSplit. zcashd could, and is end-of-life; nothing
else does.

One practical consequence for sub-spec 3: any witness cached in a wallet file is
at least five years stale, so bringing it forward means replaying every Sprout
commitment since it was written. That is cheaper than indexing from genesis, but
it is not the shortcut the note-preservation work was hoping for. The cached
witness gives a starting height, not a finished answer.

## Decisions

| # | Question | Decision |
|---|---|---|
| 1 | Project scope | All three subsystems, wallet.dat as the unifying entry point |
| 2 | Sprout data source | Argos builds and owns its own Sprout index and commitment tree |
| 3 | Wallet formats in scope | **Both** zcashd `wallet.dat` and ZecWallet Lite, behind one entry point with magic-byte sniffing |
| 4 | Key-source integration | A `KeySource` trait; seed-derivation and wallet-import are peer implementations feeding an unchanged scanner |
| 5 | Format archaeology | Hand-roll both parsers in-tree; no ecosystem dependency |
| 6 | Test fixtures | Golden wallets from a pinned zcashd **and** a synthetic writer — goldens first |

### Note on decision 5

Both teams who own this problem shell out to a `db_dump` binary rather than
parsing Berkeley DB in Rust. Zallet vendors and compiles one for BDB 6.2;
`zcash/zewif-zcashd` has `src/bdb_dump.rs`. Hand-rolling is a deliberate
departure from ecosystem practice.

Accepted costs: we independently redo work two teams have done, and we do not
interoperate with the ZeWIF stack for free.

Reasons it is still right for Argos:

- No external binary executed from a signed desktop GUI app — materially better
  for the threat model and for the Windows/macOS signing setup.
- No dependency to license-vet. GitHub reports **no SPDX license** on
  `zcash/zewif`, `zcash/zewif-zcashd`, or `zingolabs/zewif-zwl`, which would
  block adoption under the project's dependency policy regardless.
- The hostile-input surface stays in-tree where the threat model can see it.

**zcashd uses Berkeley DB 6.2**, not 4.8. Per the Zallet book, `db_dump` must be
"built for Berkeley DB version 6.2 (the version `zcashd` uses)".

## Architecture

### New crate: `crates/argos-wallet-import`

A separate crate, not a `zeck-core` module. Its entire job is consuming an
untrusted binary file supplied by a user who may have been handed it by an
attacker, and emitting spending keys. As a crate with **no network access, no
filesystem writes, and a minimal dependency set**, the question "what can a
malicious wallet.dat do?" has a crate-shaped answer instead of requiring review
of all of `zeck-core`. It is also the natural fuzzing unit.

### Components

```
sniff.rs      magic-byte dispatch → WalletFormat::{Zcashd, ZecwalletLite}
  │
  ├─ bdb.rs       read-only Berkeley DB 6.2 btree walker.
  │               Format-agnostic: yields (key_bytes, value_bytes).
  │               Knows nothing about Zcash. Primary fuzz target.
  │    │
  │    └─ zcashd.rs   record layer: `key` / `ckey` / `zkey` / `czkey` /
  │                   `sapzkey` / `csapzkey` / `sapzaddr` / `mkey` / `hdchain`.
  │                   Owns the passphrase KDF and AES-256-CBC decryption,
  │                   including `czkey`.
  │
  └─ zwl.rs       ZecWallet Lite length-prefixed reader, versioned schema.

keys.rs       ImportedKeys — the single normalized output type.
              Transparent / Sapling / Sprout key sets, provenance-tagged.
              Carries cached Sprout note data and witnesses when present.
```

The `bdb.rs` / `zcashd.rs` split is load-bearing. Page and btree decoding is
where offset-and-length bugs live; key semantics is where crypto bugs live.
Different failure modes, different review, different tests — so they do not
share a file.

`bdb.rs` has no Zcash knowledge, no network, and no filesystem access, so the
blast radius of a parser bug is "garbage records", not "key exfiltration".

#### `czkey` is day-one scope

Encrypted Sprout spending keys are the precise gap in the ecosystem stack, not
an edge case. They belong in `zcashd.rs` from the first commit.

Format detail, from `zcash/zcash` `src/wallet/walletdb.cpp:125`:

```cpp
if (!Write(std::make_pair(std::string("czkey"), addr), std::make_pair(rk, vchCryptedSecret), false))
    ...
    Erase(std::make_pair(std::string("zkey"), addr));
```

The `czkey` **value is a pair** — a receiving key `rk` alongside the encrypted
secret — a different shape from `ckey`. Writing `czkey` erases the plaintext
`zkey`.

##### Verified record formats

Established against wallets written by zcashd v6.20.0 and by reading
`zcash/zcash` source. Recording it here because, for `czkey`, this is the only
written description of the format that exists — Zallet does not migrate these
records and `zewif-zcashd` refuses them, so there is nothing else to check
against.

| Record | Key remainder | Value |
|---|---|---|
| `zkey` | 64-byte Sprout payment address | bare 32-byte `a_sk`, **no length prefix** |
| `sapzkey` | 32-byte IVK | raw 169-byte extended spending key, **no prefix** |
| `key` | CompactSize(33) + 33-byte pubkey | CompactSize + DER + 32-byte hash; the secret starts **8 bytes into the DER** (`30 81 <len> 02 01 01 04 20`) |
| `czkey` | 64-byte Sprout payment address | fixed 32-byte `rk` (**a `uint256`, not length-prefixed**) followed by the length-prefixed ciphertext |
| `ckey` | serialized public key | length-prefixed ciphertext |
| `csapzkey` | 32-byte IVK | 169-byte `extfvk` then the length-prefixed ciphertext |

**IV derivation is not uniform.** Each record's AES-256-CBC IV comes from that
record's own public identifier, which is why one master key opens every record —
but the identifier and the hash differ by record type:

- `ckey`, `czkey`: `SHA256d(identifier)[0..16]`, where the identifier is the
  serialized public key and the 64-byte Sprout address respectively.
- `csapzkey`: **not** SHA256d of the IVK. The identifier is
  `extfvk.fvk.GetFingerprint()` — BLAKE2b-256 personalized `"ZcashSaplingFVFP"`
  over `ak || nk || ovk`.

Two details that are easy to get wrong and fail silently rather than loudly:

- `extfvk` is **169 bytes, not 165**. zcashd serializes a `parentFVKTag`
  (`uint32`) that is not obvious from `zip32.h` on a first read.
- The `key` DER header must be **validated, not assumed**. A short-form header
  (`30 25 ...`, seven bytes rather than eight) yields the genuine secret shifted
  by one byte — a well-formed secp256k1 key for an address the user does not
  control, produced with no error. Real zcashd records always use the long form,
  so fixtures alone do not catch this.

#### `ImportedKeys` preserves Sprout note data and witnesses

wallet.dat caches them and sub-spec 3's cost depends on whether they are usable.
Preserving them costs almost nothing now; discarding them at this layer would be
irreversible.

### Integration boundary

`zeck-core` gains a `KeySource` trait:

- `SeedKeySource` wraps today's `derivation.rs` gap-scanning.
- `ImportedKeySource` wraps `ImportedKeys`.

Scanner and sweeper take `&dyn KeySource` and stop knowing where keys came from.

`workspace.rs`'s resume invariant generalizes from `seed_fingerprint` to a
`KeySourceFingerprint` that both implementations produce. This preserves the
invariant's meaning — change the keys, start a fresh scan — without
special-casing imports.

This trait is the seam sub-spec 3 plugs into when Sprout keys arrive from a
third source, which is why the refactor happens now rather than afterwards.

## Data flow

```
wallet file path
  │
  ├─► sniff.rs ──► WalletFormat
  │
  ├─► [Zcashd]  bdb.rs walk ──► (key, value) pairs
  │                │
  │                └─► zcashd.rs classify records
  │                       │
  │                       ├─ mkey present? ──► prompt passphrase
  │                       │                     └─► derive master key ──► decrypt
  │                       │                          ckey / czkey / csapzkey
  │                       └─ plaintext key / zkey / sapzkey
  │
  ├─► [ZecwalletLite]  zwl.rs ──► versioned records
  │
  └─► ImportedKeys ──► ImportedKeySource : KeySource
                              │
                              └─► existing scanner / sweeper, unchanged
```

Decryption is the only interactive point and happens **once, before any network
access**. A wallet file needing a passphrase fails fast and locally; lightwalletd
is never contacted before we know we have usable keys.

## User surface

### CLI

`--wallet-file <PATH>` joins `--seed-file` as a **global** flag, the two mutually
exclusive (`conflicts_with`). Key provenance is a property of the whole
invocation, not of a subcommand — which follows from the `KeySource` decision.

- **No new subcommands.** `show-keys`, `scan`, and `sweep` all work unchanged.
  `show-keys` is already documented as "derive and display all account keys";
  under `KeySource` it becomes "display all keys from the active source" and
  serves wallet-file inspection for free.
- **`--birthday`, `--birthday-date`, `--birthday-auto-detect`, `--gap-limit`, and
  `--num-accounts` must `conflicts_with` `--wallet-file` and error loudly.**
  Imported keys have no derivation path to gap-scan, and wallet.dat carries its
  own birthday information. Silently ignoring a birthday flag would let a user
  believe they had constrained a scan they had not.
  `command_uses_birthday_inputs` becomes a function of key source as well as
  subcommand.
- **The passphrase is never a flag.** Prompt-only via `dialoguer::Password`,
  matching existing seed handling. A `--passphrase` flag would leak to shell
  history and `ps`. If scripting demand appears later, the answer is stdin, not
  argv.
- **TOS gating is unchanged.** `--accept-tos` still gates network and
  funds-moving commands; wallet-file import does not change which those are.

### GUI

A second entry point alongside seed entry — "Recover from wallet file" — with a
native file picker. Requires Tauri capability changes in
`gui/src-tauri/gen/schemas/capabilities.json`, since file-dialog and read access
are not currently granted.

## Error handling

### Partial recovery beats clean failure

This inverts normal parser design. A recovery tool that refuses a wallet because
3 of 50 records are malformed has destroyed value for keys it could have read.

`bdb.rs` and `zcashd.rs` **collect errors per-record and continue**, returning
`(ImportedKeys, Vec<ImportDiagnostic>)`. Zallet reached the same conclusion from
the other direction: its `--allow-warnings` flag exists because real wallets that
touched consensus forks contain unparseable transactions.

**A record we cannot parse must never silence a record we can.** Every skipped
record is reported with counts and record types, never swallowed.

Only three conditions fail the whole import:

1. Unrecognized magic — not a wallet file.
2. Wrong passphrase.
3. A structurally unwalkable btree.

### Wrong passphrase must be distinguishable from corruption

If these collapse into one error, a user with a *correct* passphrase and a
slightly damaged wallet is told their passphrase is wrong and gives up on
recoverable funds. The `mkey` record carries enough to verify the derived key
independently of record decryption, so the distinction is available and worth
the code to preserve.

`ZeckError` gains a single `Import(ImportError)` variant; `ImportError` carries
the specific cases.

### Hostile input rules for `bdb.rs`

These apply to the parser crate and are enforced, not aspirational:

- **No panics reachable from input.** No indexing, no slicing, no `unwrap` or
  `expect` on parsed values.
  `#![deny(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]`
  at the crate root.
- **Resource bounds before allocation.** Every length field is validated against
  remaining file size before any `Vec::with_capacity`. A 4-byte length claiming
  4 GB must not allocate.
- **Cycle detection.** Btree page pointers form an attacker-controlled graph. The
  walker tracks visited pages and bounds traversal depth. Without this, a crafted
  file is a trivial infinite loop or stack overflow.

### Secret hygiene

The passphrase is `SecretString` end to end, consistent with
`docs/secret-memory-evaluation.md`'s decision to keep `secrecy` — same known
limitation (no `mlock`, swap-reachable), same accepted rationale. Decrypted key
material zeroizes on drop.

Argos never writes the wallet file, decrypted keys, or the passphrase to disk.
Imported key material enters the workspace only in forms the existing scanner
already persists.

## Threat model changes

`docs/THREAT_MODEL.md` needs substantive edits:

| Section | Change |
|---|---|
| §2.1 Components, §2.2 Data flow | Add the import crate and the file-input path |
| §3 Assets | New asset: **the user's wallet file** — a single artifact holding all their spending keys, higher-value than a seed for a zcashd user with imported keys |
| §5 Threat actors | New vector: **a malicious wallet file**. Argos previously accepted only a mnemonic — a low-structure, low-surface input. Accepting an attacker-crafted binary is a genuinely new actor path. |
| §6.1 Secret handling | Passphrase handling, and the Tauri IPC plaintext exposure as a **new instance of accepted audit Issue A** — stated explicitly rather than silently inherited from the seed's justification |
| §6.4 Local storage | Imported keys entering the workspace |
| §9 Out of scope, and `README.md` | Completed after the capability shipped: both now distinguish seed-only limits from end-to-end Sprout recovery using a wallet file or standalone key. |

## Testing

Per `CLAUDE.md`: capture a `cargo test` and clippy baseline on `main` **before**
any changes, so the `KeySource` refactor's blast radius is measurable rather than
asserted.

### Layers

| Layer | What it proves | Artifact |
|---|---|---|
| **Golden wallets** | Our format understanding matches the real producer | Pinned zcashd Docker service, opt-in compose profile in `tests/regtest/docker-compose.yml`, following the existing `zfnd/zebra:6.2.3` / `electriccoinco/lightwalletd:v0.5.1` pinning pattern. Runs only when regenerating; committed `.dat` blobs otherwise. |
| **Synthetic matrix** | Every record type, corruption, and encryption variant | Test-only BDB writer. Deterministic, diffable, no EOL binary in the loop. |
| **Fuzzing** | No panic, OOM, or hang on arbitrary bytes | `cargo-fuzz` target on `bdb.rs`, seeded from the goldens |
| **Integration** | The `KeySource` refactor did not regress seed recovery | Existing `crates/zeck-core/tests/regtest_integration.rs` suite, unchanged, stays green |

**Ordering matters: goldens first.** A test-only writer validated against our own
reader is a self-consistent misreading that passes every test. Real
zcashd-written files anchor the format understanding; only then do we build the
writer for the exhaustive matrix.

### Sprout fixture generation — resolved

The concern that modern zcashd cannot create Sprout addresses is **false**.
`zcashd` v6.20.0 (latest, released 2026-06-03) still generates them.
From `src/wallet/rpcwallet.cpp:3236`:

```cpp
if (addrType == ADDR_TYPE_SPROUT) {
    if (chainparams.GetConsensus().NetworkUpgradeActive(chainActive.Height(), Consensus::UPGRADE_CANOPY)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid address type, \""
                           + ADDR_TYPE_SPROUT + "\" is not allowed after Canopy");
    }
    ...
    return keyIO.EncodePaymentAddress(pwalletMain->GenerateNewSproutZKey());
}
```

The only gates are Canopy activation and initial block download. On regtest,
activation heights are configurable — the same mechanism
`crates/zeck-core/src/workspace.rs:144` already uses to force every upgrade
active, inverted. Hold Canopy inactive and `GenerateNewSproutZKey()` writes a
real `zkey` record. Running `encryptwallet <passphrase>` then converts it to
`czkey` and writes `mkey`.

**We can therefore generate golden `czkey` fixtures written by the real
producer** — for the one record type with no reference implementation anywhere.

Two chain configurations, one pinned image (`zcashd:v6.20.0`), no ancient binary:

| Config | Canopy | Produces |
|---|---|---|
| Pre-Canopy | inactive | `zkey`, then `czkey` + `mkey` after `encryptwallet` |
| All upgrades active | active | `sapzkey` / `csapzkey`, transparent `key` / `ckey` |

Golden set covers at minimum: unencrypted, encrypted with a known passphrase,
transparent-only, Sapling-bearing, Sprout-bearing, multi-account, and a
deliberately truncated or corrupted copy of each.

### TDD shape

Per-record-type, red-green: a failing test asserting that a specific record
parses to specific key material, then the parser code.

`czkey` decryption gets the most tests. It has no reference implementation
anywhere, so **our tests are the specification**.

## Open questions

Carried forward; none block sub-spec 1 implementation.

1. **Full-block source for sub-spec 3** — Zebra `getblock` endpoint, explorer
   API, or something else. Decide in sub-spec 3's brainstorm.
   (Resolved separately: V4 transactions remain accepted post-Ironwood, so the
   sub-spec is worth building.)
2. **Are wallet.dat's cached `SproutWitness` values usable** after being brought
   forward? Determines whether sub-spec 3 must index from genesis.
3. **Licensing of the ZeWIF repos.** Not a dependency blocker any more given
   decision 5, but it gates the optional `zewif-zcashd` cross-validation oracle.
   Zallet also does not support regtest wallet migration, so testnet goldens may
   be required for that comparison.
4. **`gui/src-tauri/gen/schemas/capabilities.json` is dirty in the working tree**
   and must be resolved before GUI capability changes land.

## Out of scope

- Sweeping to Ironwood (sub-spec 2)
- Sprout scanning, witness construction, and JoinSplit building (sub-spec 3)
- Writing wallet files in any format
- ZeWIF interchange output
- Migrating Argos's own workspace format
