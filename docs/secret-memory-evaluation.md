# Evaluation: locking secret material into volatile memory (audit Suggestion 9)

**Status:** recommendation — no code change. **Decision: keep `secrecy` for now.**

## Background

Least Authority audit Suggestion 9 notes that the threat model states Argos
avoids writing the seed to disk and explicitly names writing it to swap as a
threat, while also acknowledging that `secrecy` does not protect against swap.
The suggestion is to *consider* alternatives that prevent the OS from paging
sensitive data to disk — `secrets` or `shush-rs` — both of which can `mlock`
secret pages.

`secrecy` zeroizes on drop but does **not** `mlock`: nothing stops the kernel
from paging a live `SecretString` to swap, or capturing it in a core dump,
before it is dropped.

## Candidates (data as of 2026-06-22, crates.io)

| Crate | Version | Downloads (recent) | Last release | Memory protection | Extra deps |
|---|---|---|---|---|---|
| **secrecy** (incumbent) | 0.10.3 | 122M (27.9M) | 2024-10 | zeroize-on-drop only | none beyond `zeroize` |
| **secrets** | 1.3.0 | 76k (7.5k) | 2026-04 | `mlock` + `mprotect` guard pages + canaries, via **libsodium** | `libsodium-sys` (C library) |
| **shush-rs** | 0.1.11 | 13.8k (0.3k) | 2024-11 | `mlock`/`munlock` + zeroize, `secrecy`-style API | `libc` only |

(`secrecy` is maintained by iqlusion; it is the de-facto standard, hence the
122M downloads.)

## Analysis

**What `mlock` actually buys us.** `mlock` keeps pages resident so they are not
written to swap, and reduces (not eliminates) core-dump exposure. It does
nothing against an attacker who can already read the process's live memory, and
nothing about the cleartext seed that — per audit Issue A — unavoidably transits
the Tauri IPC as plaintext JSON and through serde parse buffers before any
wrapper can seal it. The strongest mitigation (encrypted or disabled swap) is an
OS-level control the audit itself places outside an individual application.

**`secrets` — strongest protection, highest cost.** libsodium guarded
allocations are the gold standard, but `libsodium-sys` introduces a C build
dependency. Argos ships a cross-platform Tauri matrix (macOS, Linux, Windows
x64 **and ARM64**) with a code-signing release pipeline (audit Issues G/H, PR
#96). Adding a bundled/linked C library to that matrix is a material build- and
release-integrity risk for a modest in-memory benefit — it directly complicates
the pipeline we are otherwise hardening.

**`shush-rs` — lowest-friction, but immature.** It mirrors `secrecy`'s API
(`SecretBox`) and adds `mlock` with only a `libc` dependency, so it would be a
near drop-in. But it is 0.1.x, ~14k downloads, single-maintainer, and ~19 months
since its last release as of this writing. Swapping the crate that wraps the
**wallet seed** — our most security-critical value — from a battle-tested
dependency (122M downloads) to an unproven one trades a known quantity for
maintenance and correctness risk in exactly the wrong place.

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
   access to in-scope. If so, the lowest-friction path is to pilot `shush-rs`
   behind a focused review, or to `mlock` only the seed buffer via a small
   `region`/`memsec`-based wrapper rather than replacing `secrecy` wholesale.
3. **Keep the exemption/audit posture** ([supply-chain/README.md](../supply-chain/README.md))
   in mind: any of these alternatives adds a new dependency that would itself
   need vetting.

This keeps Argos aligned with the broad Zcash-ecosystem dependency set (which
standardizes on `secrecy`) while recording the deliberate decision and the
conditions under which we would reconsider.
