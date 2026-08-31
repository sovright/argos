# Evaluation: locking secret material into volatile memory (audit Suggestion 9)

**Status:** recommendation — no code change. **Decision: keep `secrecy` for now.**

## Background

Least Authority audit Suggestion 9 notes that the threat model states Argos
avoids writing transient recovery secrets to disk and explicitly names writing
them to swap as a threat, while also acknowledging that `secrecy` does not
protect against swap. The original evaluation focused on the seed; the same
reasoning now applies to wallet passphrases and standalone Sapling/Sprout keys.
The deliberately persistent, spend-capable Sprout scan checkpoint is a
separate T-L7 storage decision, not something `mlock` can address.
The suggestion is to *consider* alternatives that prevent the OS from paging
sensitive data to disk — for example `secrets`, or `shush-rs` after source
review confirms it locks the actual secret backing memory Argos would use.

`secrecy` zeroizes on drop but does **not** `mlock`: nothing stops the kernel
from paging a live `SecretString` to swap, or capturing it in a core dump,
before it is dropped.

## Candidates (data as of 2026-06-22, crates.io)

| Crate | Version | Downloads (recent) | Last release | Memory protection | Extra deps |
|---|---|---|---|---|---|
| **secrecy** (incumbent) | **0.8.0** (in tree; crate latest 0.10.3) | 122M (27.9M) | 2024-10 | zeroize-on-drop only | none beyond `zeroize` |
| **secrets** | 1.3.0 | 76k (7.5k) | 2026-04 | `mlock` + `mprotect` guard pages + canaries, via **libsodium** | system libsodium by default (`pkg-config`/vcpkg), optional bundled `libsodium-sys` |
| **shush-rs** | 0.1.11 | 13.8k (0.3k) | 2024-11 | advertises `mlock`/`munlock` + zeroize for its own allocations; needs source audit for Argos seed buffers | `libc` only |

(`secrecy` is maintained by iqlusion; it is the de-facto standard, hence the
122M downloads. Argos pins the 0.8.x API — `Secret<T>` / `SecretString::new(String)`.
Note that `secrecy` 0.10 replaced `Secret<T>` with `SecretBox<T>` and changed
`SecretString::new` to take `Box<str>`, so even *upgrading* secrecy is a
breaking migration — and `shush-rs` deliberately mirrors that 0.10 `SecretBox`
API, making a swap to it a larger change than the version numbers suggest. This
strengthens the "don't swap" conclusion below.)

## Analysis

**What `mlock` actually buys us.** `mlock` keeps pages resident so they are not
written to swap, and reduces (not eliminates) core-dump exposure. It does
nothing against an attacker who can already read the process's live memory, and
nothing about the cleartext seed, wallet passphrase, or pasted spending key
that — per audit Issue A and T-S6/T-S7 — transits the Tauri IPC as plaintext
JSON and through serde parse buffers before any wrapper can seal it. The
strongest mitigation (encrypted or disabled swap) is an
OS-level control the audit itself places outside an individual application.

**`secrets` — strongest protection, highest cost.** libsodium guarded
allocations are the gold standard, but `secrets` still introduces a libsodium C
library dependency (system-provided via `pkg-config`/vcpkg by default, or
optionally bundled through `libsodium-sys`). Argos ships a cross-platform Tauri
matrix (macOS, Linux, and Windows x64) with a code-signing release pipeline
(audit Issues G/H, PR #96). Adding a bundled/linked C library to that matrix is
a material build- and release-integrity risk for a modest in-memory benefit —
it directly complicates the pipeline we are otherwise hardening.

**`shush-rs` — potentially lower-friction, but immature and unaudited here.**
It mirrors `secrecy` 0.10's `SecretBox` API and advertises `mlock` with only a
`libc` dependency, so it is worth revisiting only after a focused source review
confirms the bytes that hold Argos recovery material would actually be page-locked.
It is also 0.1.x, ~14k downloads, single-maintainer, and ~19 months since its
last release as of this writing. Swapping the crate that wraps **recovery
secrets** — our most security-critical values — from a battle-tested dependency
(122M downloads) to an unproven one trades a known quantity for maintenance and
correctness risk in exactly the wrong place.

## Recommendation

**Do not swap `secrecy` now.** The marginal benefit (anti-swap for short-lived
in-RAM secrets in a single-use desktop tool) does not justify either (a) a
libsodium C dependency through the signed cross-platform release pipeline
(`secrets`), or (b) moving seed handling onto an immature 0.1.x crate
(`shush-rs`).

Instead:

1. **Document the OS-level mitigation for users** (the real control): run
   recovery on a machine with encrypted swap, or with swap disabled, and avoid
   suspend/hibernate during a recovery. This belongs in the user guide.
2. **Revisit if the threat model elevates** a local attacker with swap/core-dump
   access to in-scope. If so, first source-audit `shush-rs` to verify it locks
   the actual secret backing memory Argos would use before piloting it; otherwise
   prefer `mlock`ing only the seed buffer via a small `region`/`memsec`-based
   wrapper rather than replacing `secrecy` wholesale.
3. **Keep the supply-chain posture** (the `cargo vet` config in
   [supply-chain/config.toml](../supply-chain/config.toml) and the audit
   discussion in [THREAT_MODEL.md](THREAT_MODEL.md)) in mind: any of these
   alternatives adds a new dependency that would itself need vetting.

This keeps Argos aligned with the broad Zcash-ecosystem dependency set (which
standardizes on `secrecy`) while recording the deliberate decision and the
conditions under which we would reconsider.
