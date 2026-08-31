# Supply-chain review policy

Argos gates its dependency tree with two CI checks:

- **`cargo vet`** (`supply-chain/config.toml`, `audits.toml`, `imports.lock`) —
  every third-party crate must be covered by an imported audit, a first-party
  audit, or an exemption.
- **`cargo deny`** (`deny.toml`) — advisories, license allow-list, banned
  crates, and source restrictions.

This document defines how we treat those gates. It exists because the audit
(Least Authority, June 2026, **Issue F**) found that the `cargo vet`
configuration gave the *appearance* of supply-chain review while the most
security-relevant crates were covered by blanket exemptions rather than review.

## The exemption trap

A `cargo vet` **exemption** is a standing waiver: the crate is accepted with no
audit record. As of the NU6.2 dependency wave there are **574** exemptions
(`grep -c '^\[\[exemptions\.' supply-chain/config.toml`). An exemption is *not*
a review — it is the absence of one. Critically, when a dependency is bumped,
the new version needs a fresh exemption, and accepting that as a one-line change
during an otherwise routine update is enough to let a compromised point release
through **without anyone reading the code it covers**.

The exemption count is a metric to **drive down over time**, not a number to let
grow with the tree. `574` (NU6.2) is the current baseline; new work should not
increase it without justification.

## Recovery-secret-handling-critical crates

These crates derive, hold, transmit, or sign with wallet seeds and standalone
spending keys, or terminate the TLS that protects recovery traffic. A
compromised release of any one could exfiltrate a seed or key, or subvert
signing. They must **never be accepted on the basis of a blanket exemption
alone**:

```
orchard            sapling-crypto      halo2_gadgets
zcash_primitives   zcash_keys          zcash_client_backend
zcash_client_sqlite zcash_address      zcash_protocol
zcash_transparent  zcash_proofs        zcash_encoding
zip321             secrecy             secp256k1
ring               rustls              tonic
```

## Policy

1. **Exemption changes are a review trigger.** Any PR that adds or version-bumps
   an exemption for a recovery-secret-handling-critical crate (above) MUST include, in the
   PR description, confirmation that a reviewer inspected the upstream diff
   between the previously accepted version and the new one. A dependency bump is
   not "routine" for these crates.

2. **Prefer audits or publisher-pinned trust over exemptions.** For the
   recovery-secret-handling-critical crates, convert exemptions to either a first-party
   `[[audits]]` entry (a real code review, recorded with
   `cargo vet certify`) or a publisher-pinned `[[trusted]]` entry that trusts a
   named crates.io publisher rather than waiving review entirely:

   ```sh
   # Trust a specific publisher for a crate (run by a maintainer; most of these
   # crates have multiple publishers, so the publisher login must be explicit
   # and is a deliberate trust decision):
   cargo vet trust <crate> <publisher-login> --criteria safe-to-deploy \
       --notes "Recovery-secret-handling crate; trusting the upstream publisher (audit Issue F)."
   ```

   Choosing *which* crates.io account(s) to trust is a maintainer decision and is
   intentionally not automated here.

3. **Keep CI green by content, not by waiver.** When `cargo vet` fails after a
   bump, the fix is to review and certify/trust the new version — not to widen an
   exemption silently. `cargo vet --locked` in CI enforces the recorded set.

## Imported audits

`config.toml` imports audits from seven upstream sources (Bytecode Alliance,
Embark, Fermyon, Google, ISRG, Mozilla, and Zcash). These cover 142 crates
fully and 6 partially. The Zcash import (`librustzcash`) is the most relevant to
the recovery-secret-handling set and should be re-pulled on each librustzcash bump
(`cargo vet` updates `imports.lock`).
