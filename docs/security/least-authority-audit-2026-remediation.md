# Argos — Least Authority Initial Audit: Remediation Status

> **Canonical, org-owned copy.** This document is the authoritative record of the
> Least Authority audit remediation, version-controlled in `sovright/argos`. It
> supersedes any personal-account gist copy so the record does not depend on an
> individual's account. Keep it updated here.

**Audit:** Least Authority TFA GmbH, Initial Audit Report, 22 June 2026
**Audited revision:** `78ffb4dde8582a25934b25ee798ec4f194a6bd0f`
**Repository:** `sovright/argos`
**Status:** ✅ **All findings remediated and merged to `main`** (as of 24 June 2026).

One branch + one PR per finding; every PR built clean (`cargo build` / `clippy --all-targets`) with tests passing before merge.

## Issues

| ID | Severity | Finding | Resolving PR(s) |
|----|----------|---------|-----------------|
| A | Medium (Impact High) | Seed crosses the GUI boundary as a plain `String` with `Debug`/`Serialize` derives | [#123](https://github.com/sovright/argos/pull/123) |
| B | Medium | Broadcast and confirmation trust a single server | [#126](https://github.com/sovright/argos/pull/126) (single-server disclosure) + [#145](https://github.com/sovright/argos/pull/145) (second-endpoint cross-check) |
| C | Medium | Birthday auto-detection allows a malicious server to hide funds | [#125](https://github.com/sovright/argos/pull/125) (late-birthday caution) + [#144](https://github.com/sovright/argos/pull/144) (cross-endpoint minimum) |
| D | Medium (Impact High) | `opener:default` grants seed-exfiltration egress that bypasses the CSP | [#124](https://github.com/sovright/argos/pull/124) (also resolves Suggestion 8) |
| E | Medium | A mid-sequence sweep failure discards the record of transactions already broadcast | [#115](https://github.com/sovright/argos/pull/115) |
| F | Medium (Impact High) | `cargo-vet` exemptions distort the view of supply-chain risk | [#143](https://github.com/sovright/argos/pull/143) (review policy + seed-handling crates converted to publisher-pinned `[[trusted]]`) |
| G | Medium (Impact High) | Windows signing DLL downloaded without a hash check | [#116](https://github.com/sovright/argos/pull/116) |
| H | Medium (Impact High) | Headline release-verification instruction is circular | [#117](https://github.com/sovright/argos/pull/117) |
| I | Low | Reconnect after a transport error skips network revalidation | [#118](https://github.com/sovright/argos/pull/118) |

## Suggestions

| ID | Suggestion | Resolving PR(s) |
|----|------------|-----------------|
| 1 | Validate the destination address network at entry | [#133](https://github.com/sovright/argos/pull/133) |
| 2 | Remove temporary directory upon error | [#132](https://github.com/sovright/argos/pull/132) |
| 3 | Create workspace files with explicit `0o600` permissions | [#119](https://github.com/sovright/argos/pull/119) |
| 4 | Use checked arithmetic for zatoshi additions | [#121](https://github.com/sovright/argos/pull/121) |
| 5 | Reject a zero Sapling activation height | [#120](https://github.com/sovright/argos/pull/120) |
| 6 | Redact mistyped seed words from error messages | [#122](https://github.com/sovright/argos/pull/122) |
| 7 | Restrict the release tag trigger | [#129](https://github.com/sovright/argos/pull/129) |
| 8 | Remove the unused `reveal_item_in_dir` grant | Resolved within [#124](https://github.com/sovright/argos/pull/124) (Issue D) |
| 9 | Lock sensitive data to volatile memory | [#130](https://github.com/sovright/argos/pull/130) (decision record: keep `secrecy`; rationale documented) |
| 10 | Differentiate threat model from threat assessments | [#131](https://github.com/sovright/argos/pull/131) |
| 11 | Clarify presentation of trust relationships | [#131](https://github.com/sovright/argos/pull/131) |
| 12 | Clarify definition of threat actors | [#131](https://github.com/sovright/argos/pull/131) |
| 13 | Revise priority of asset "Recovery Report" | [#131](https://github.com/sovright/argos/pull/131) |

## Notes

- **Issues B and C** each ship the report's stated minimum (disclosure / surfaced caution) *plus* the recommended second-endpoint cross-check (B → #145, C → #144).
- **Issue F** (#143): every seed-handling-critical crate (`orchard`, `sapling-crypto`, the `zcash_*` set, `secrecy`, `secp256k1`, `ring`, `rustls`, `tonic`, …) is converted from a blanket `safe-to-deploy` exemption to a publisher-pinned `[[trusted]]` entry, each pinned to the crates.io account that published the in-tree version. 19 `[[trusted]]` entries; exemption count reduced from 574 to 555. A `supply-chain/README.md` documents the policy (exemption changes are a review trigger; drive the count down over time).
- **Suggestion 7** (#129) documents the requirement in-tree; the actual gate is an out-of-tree GitHub Environment protection setting, and it is **verified configured** in repo settings (checked 24 June 2026): both the `release-sign` and `release-publish` environments require reviewer approval (2 reviewers), and `release-sign` — which holds the Apple/Azure code-signing secrets — is additionally restricted to `v*` tags. A `v*` tag push therefore cannot reach the signing or publish steps without an approved reviewer. (Minor optional hardening: `release-publish` currently has no deployment branch/tag restriction; it could be pinned to `v*` for consistency, though it requires review and holds no secrets.)
- **Suggestion 9** (#130): evaluated `secrets` and `shush-rs`; recommendation is to keep `secrecy` (`secrets`' libsodium C-dependency would burden the signed cross-platform release pipeline; `shush-rs` is immature for seed handling). To revisit if the threat model elevates a local swap/core-dump attacker.
- A separate CI-repair PR ([#127](https://github.com/sovright/argos/pull/127)) refreshed `cargo-vet` exemptions for the NU6.2 dependency wave and ignored `RUSTSEC-2026-0173` (unmaintained transitive `proc-macro-error2`); not an audit finding.

All findings from the Initial Audit Report are addressed and merged to `main`.

---

### Provenance

This file was vendored into the repository on 24 June 2026 from the remediation
summary that had been maintained in a personal gist
(`gist.github.com/zmanian/5c9789f16103695475b235de9bac0209`). Future updates
should be made here, in-repo, and the gist treated as a stale mirror. The full
Least Authority PDF report should likewise be stored under org control (e.g.
attached to a release or committed here) rather than only shared via chat.
