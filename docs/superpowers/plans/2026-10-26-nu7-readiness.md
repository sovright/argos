# NU7 recovery readiness

This change implements recovery compatibility with NU7. It is not a release
qualification claim for funded production wallets.

## Protocol authority

- [ZIP 259](https://zips.z.cash/zip-0259): mainnet activation **3,543,405**,
  testnet **4,465,026**, branch **0x77190AD9**; peer protocol minimums
  **170190** mainnet and **170180** testnet. V4 is invalid at activation;
  existing v5/v6 signatures also remain bound to their original branch.
- [ZIP 2003](https://zips.z.cash/zip-2003): retire Sprout spending while
  retaining historical data. A transaction must be mined before activation;
  broadcasting earlier is insufficient. At tip A-1 the next block is already
  too late for a new Sprout submission.
- [ZIP 218](https://zips.z.cash/zip-0218): 25-second target spacing,
  120-block default expiry after the target height, Sapling inputs+outputs
  <=300 and combined shielded cost <=330, including padding. Transparent
  inputs are outside this shielded budget.
- [ZIP 235](https://zips.z.cash/zip-0235): fee removal is a block-level rule;
  it does not require a wallet burn output or an automatic fee increase.

## Implementation decisions

The published October 21 NU7 SDK family is upgraded together, including
protocol, primitives, proofs, wallet backend, SQLite, PCZT, keys, transparent,
address, Orchard, Sapling, and their shared cryptographic types. Rust 1.89 is
used in the workspace, CI and release builds. Historical key/transaction
fixtures retain their provenance and secret-erasure checks.

Sprout spending requires a fresh network-validated height before proving,
a second check after proving, and a fresh check on each exact-byte retry.
Configured evidence at the deadline stops new work despite a lagging primary.
Unavailable, stale or mismatched evidence disables new spending. RPC evidence
is not independent consensus verification. At least one usable configured
source is required; a source failure is disclosed, never counted as agreement.

Retirement does not create a successful recovery, a mined confirmation, or
an invented expiry. Unmineable rows retain their value, lifecycle and bytes.
Ordinary expiry still requires its existing evidence. Inspection, decryption,
history and observation-only reconciliation remain available. GUI spending
permission is bound to the exact reviewed proposal for 60 seconds; a request
can narrow that authority to status-only, and cannot widen it.

Every normal recovery submission and explicit retry also checks signed branch,
transaction version, expiry and actual bundle counts against the fresh next
block. Reviewed proposal identities include the branch even where the wire
version stays v6. Already-signed bytes are never rewritten to cross an upgrade.

Oversized send-max selections become disjoint bounded steps. All selected
notes, payment memos and reviewed donation proportions are retained. Value-aware
batch allocation helps each transaction pay its own fee; impossible allocations
fail explicitly. Aggregate quote fees and cumulative execution limits cover all
steps, and earlier submission evidence survives later failure.

Date estimation uses real block timestamps online. Offline dating remains
conservative and does not invent a calendar activation date. Known-height
estimates account for 150/75/25-second eras. The date safety margin retains at
least its historical duration after NU7. The 20-block expiry margin,
10-confirmation discard depth, and 20-block transparent quote age remain
explicit depth policies. Scanner rollback retention becomes 600; the separate
100-block authenticated checkpoint-cleanup policy remains compatible with
existing journals.

## Qualification and release boundary

The primary dirty checkout is preserved. This isolated branch starts at PR
#290 (`a8ff8b7`), retaining the separate advisory and retry fixes.

Offline gates cover both production schedules, real-branch v5/v6 wire and
PCZT encoding, builder expiry, old-SDK SQLite migration, existing account/scan
work, padded limits, branch-bound review, retry guards and partial success.
A separate fast Zebra 7 / lightwalletd 0.6 profile exercises actual blocks and
proxy decoding across activation. It does not establish funded sweep or
signed PCZT acceptance. The original pre-Canopy Sprout profile is preserved.

Before release, run the full-height funded synthetic-wallet rehearsal for
transparent, Sapling, Orchard, Ironwood and imported Sapling PCZT recovery.
Record mined transactions, pending transactions crossing activation, and
reorg/proposal invalidation. See [regtest instructions](../../../tests/regtest/README.md#dedicated-nu7-qualification).

The supply-chain policy uses refreshed existing audit imports and exact-version
exemptions for uncovered dependencies. Exemptions do not assert a source audit;
newly exempted versions explicitly retain outstanding-audit notes.
