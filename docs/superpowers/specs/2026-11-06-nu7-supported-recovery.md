# NU7 supported recovery after Sprout removal

## Scope
Carry the supported-recovery parts of PR #291 (850697b) onto merged PR #301 (e5e0fe4). Keep transparent, Sapling, Orchard and Ironwood recovery compatible with NU7. Do not restore Sprout spending, inspection machinery, P2P, journals, UI or dependency-only proving code.

## Requirements
- Upgrade the coordinated SDK family to backend 0.25, SQLite 0.23, protocol 0.11, primitives/proofs 0.31, keys 0.17, PCZT 0.10, Orchard 0.16, Sapling 0.9 and Rust 1.89. Preserve newer security fixes from main and exact-version cargo-vet policy.
- Bind reviewed proposals to consensus branch; validate fresh network tip, transaction version, branch, expiry and actual padded shielded bundle limits before every submission and exact-byte retry. Keep signed bytes and prior outcomes unchanged when validation fails.
- Bound send-max transactions to Sapling IO <=300 and combined shielded budget <=330. Preserve all selected notes, recipient/memo/donation accounting, aggregate fee authorization and partial-success evidence. Refuse to continue on unknown broadcast outcome.
- Use network-aware birthday estimation, conservative offline bounds and NU7 spacing without reducing the historical safety margin. Retain existing depth policies except upstream scanner rollback retention needed by the SDK.
- Preserve #301 TOS ordering, supported-only fingerprints, Sprout count/notice behavior and private filesystem protections.
- Port migration fixtures, boundary/regression tests, independent NU7 profiles and CI. Do not claim empty fixtures or coinbase/proxy tests prove funded recovery.

## Qualification boundary
Run all feasible local unit/integration, GUI, strict Clippy, dependency and workflow checks; run independent review and PR CI. A funded full-height rehearsal covering supported sweeps and imported Sapling PCZT remains a release gate until actually executed and recorded. No release or mainnet spending is authorized by this change.
