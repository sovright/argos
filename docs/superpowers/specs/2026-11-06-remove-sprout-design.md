# Remove Sprout recovery after NU7

Approved by the user on 2026-11-06: remove Sprout recovery functionality because NU7 disallows v4 transactions, the only format supporting Sprout spends. Keep minimal wallet-record recognition to explain that Sprout funds are unspendable under NU7 while continuing transparent and Sapling wallet recovery.

Remove core scanning, proving, witnesses, sweeping, journals, full-block P2P, pack construction/download, CLI commands/inputs and GUI flows, their dedicated dependencies, tests and active documentation. Preserve supported-pool recovery, encrypted wallet import, existing user files, and shared filesystem protections. Do not delete on-disk user checkpoints or wallets.

## Approaches

Removing only the UI would leave unsupported recovery code and dependencies. Retaining a historical Sprout scanner would retain most of the maintenance and security surface without a supported spend path. The approved approach removes the full recovery implementation and retains only recognized-record counts and a factual notice; no Sprout secrets or note data are imported.

This change does not claim general NU7 compatibility for the remaining upstream transaction stack, and does not merge the independent NU7-readiness PR.
