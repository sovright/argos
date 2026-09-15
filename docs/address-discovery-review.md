# Address discovery: security and usability review

This review covers the offline matcher, GUI handoff, and additions to the
existing recovery pipeline. It does not replace a funded-chain recovery test
or an independent security audit.

## Findings addressed

- **Wrong derivation on recovery:** matching now records account, scope, index,
  pool, network, and the derived receiver. The backend re-derives the selected
  receiver before supplying its key source to recovery. The GUI sends opaque
  IDs rather than a replacement derivation path or seed.
- **Unknown indices beyond an unused-address gap:** offline discovery checks
  the entire requested range; it does not use balance activity to stop early.
- **False Unified Address ownership:** receivers are decoded and compared
  independently. Results identify the matched pool and explain that other
  receivers may belong to different keys.
- **Incorrect Sapling internal labels:** Sapling discovery derives external and internal
  viewing keys separately and verifies the exact scope/index during handoff.
  Imported Sapling sweeping selects proof authority by each note recipient
  and rejects unknown or missing recipient scope.
- **Secret retention during close and handoff:** form inputs clear on
  submission/close, pending start responses have a stale-response guard, and
  close waits for cancellation before releasing the retained job. Search results remain available for sequential recovery, with recovery actions
  locked while another recovery is active. Explicit close releases the search
  independently of the active recovery key source. Search input types do
  not implement serialization or debug formatting.
- **Unbounded worker creation:** the backend registers only one retained
  search, enforces candidate/range/work limits, and keeps that registration
  until the worker stops. Account keys are cached across index candidates.
- **Lost resume provenance:** session metadata carries public coordinates and
  matched scans fail if their initial metadata cannot be written. Resume
  requires the mnemonic/passphrase combination to reproduce the address and
  the workspace fingerprint. A mismatch explicitly asks users to check the
  seed and case-sensitive BIP39 passphrase, separate from the wallet password.
- **Stale wizard inputs:** selecting a match clears previous seed, wallet-file,
  and pasted-key inputs; it fixes the network and hides irrelevant account-gap
  controls. The backend also fixes matched scan scope.

- **Ordinary recovery missed higher transparent indices:** new seed scans
  register the complete configured account-0 receive range, optionally change,
  independently of shielded account depth. The sweep uses public derivation
  coordinates to reconstruct every standalone signing key, rather than assuming
  two positional receivers per account. Raw keys are not stored in metadata.
- **Range changes mixed incompatible workspaces:** the range is part of the
  workspace identity. Resume restores the saved scope; older workspaces keep
  their original account/transparent mapping. Exact-match recovery cannot be
  widened through these controls.

## Validation and remaining limits

The automatic-range update passes 587 workspace tests (17 ignored) and 16 GUI
interaction tests, with workspace and funded-regtest compilation checked by
Clippy with warnings denied. Default-range registration, two-account ownership,
mid-registration cancellation followed by resume, range identity, and signing
coordinates are covered by offline tests.

Regression tests cover nonzero transparent account/change indices beyond a
standard gap, multiple passphrase candidates, cancellation, range and network
validation, partial Unified Address receiver matching, Sapling diversifier
behavior, exact account import, and public session metadata. GUI interaction
tests exercise submission, secret clearing, handoff, close, and a delayed start
response after close. These tests use synthetic/public seeds.

The existing sweep confirmation and destination validation remain the boundary
for sending funds. A transparent recovery uses one matched key. Shielded
recovery scans the matched account; Orchard's existing HD route can discover
other receivers in that account. No funds were moved for this review.

Native visual testing was unavailable in the agent environment. Keyboard,
small-window layout, native webview reload behavior, and funded recovery should
be checked before release. JavaScript secret strings cannot be reliably
zeroized, and the upstream cryptographic key types have their own memory
handling constraints. Search results and session coordinates are public
wallet metadata, which still deserve privacy when sharing diagnostics.

Coverage exclusions and exact search bounds are documented in
[address-discovery-profiles.md](address-discovery-profiles.md).

Ignored funded regtest regressions exercise transparent index 997 and
Sapling internal-address matching, exact-key/account recovery, sweep proposal,
and mined transaction acceptance using the existing Docker harness. These are
backend integration tests, not a substitute
for the requested native GUI funded-flow check. The local Docker daemon did
not respond during this review, so funded execution remains unverified.

An additional ignored funded regression covers normal seed recovery at indices
7 and 997 without a known-address search. It checks both addresses' UTXOs
before and after the mined sweep. This harness test must be executed along
with native GUI qualification before claiming funded end-to-end validation.
