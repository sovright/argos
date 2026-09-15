# Rustls advisory update: source review

PR #213's CI detected RUSTSEC-2026-0285 in the inherited Rustls 0.23.37
lockfile entry. The update sets the minimum and locked Rustls version to
0.23.45 and updates its certificate-validation dependency, rustls-webpki,
from 0.103.13 to 0.103.15. No other locked package versions change.

These are automated source-delta reviews by OpenAI Codex agents, recorded
under that identity in cargo-vet. They do not represent human maintainer
sign-off or an independent cryptographic audit. No publisher trust or
exemption was expanded to accept these versions.

## rustls-webpki 0.103.13 to 0.103.15

The reviewer compared the complete published source delta, including package
metadata, CRL lookup, algorithm bindings, exports, and tests:

- `src/crl/types.rs` replaces an equivalent error-propagation match with `?`;
  revoked-certificate matching continues to compare serial numbers.
- `src/aws_lc_rs_algs.rs` removes the per-algorithm FIPS-submission flag and
  reports FIPS mode through `try_fips_mode`. Algorithm identifiers and
  signature-verification bindings remain unchanged.
- `src/lib.rs` and `src/alg_tests.rs` expose ML-DSA algorithms under the stable
  AWS-LC feature. Package metadata raises the optional AWS-LC requirement and
  a development-only base64 dependency.

Argos selects Rustls's ring backend. Its active certificate parsing, CRL
lookup, and ring signature bindings have no substantive behavior change in
this delta. The optional AWS-LC changes were inspected but not executed.

## Rustls 0.23.39 to 0.23.45

Cargo-vet identified an existing imported audit baseline at 0.23.39. The
reviewer inspected the complete published delta from that baseline, including
all changed runtime files and manifests:

- Client handshake code checks that the server chose an offered cipher suite
  usable for the transport; QUIC cannot select TLS 1.2.
- Server HelloRetryRequest handling preserves the first ClientHello's PSK and
  suite constraints and rejects incompatible second-hello state before
  continuing. Retained state is bounded.
- The handshake deframer keeps alignment false while any complete or partial
  handshake span is pending, closing encryption-level boundary interleaving.
- TLS 1.2 filters unsupported signature algorithms and fails with a fatal
  alert before verification. Optional ML-DSA support is restricted to AWS-LC
  and TLS 1.3.
- OCSP, ticket truncation, age conversion, and binder-length changes reject
  malformed inputs or use checked/saturating arithmetic instead of wrapping
  or panicking.
- ECH rejection authenticates the public name and corrects padding. Ticket
  requests are bounded by configuration and byte-sized counts.
- Parsed private-key DER is zeroized. New SSL key-log files use Unix mode
  0600; existing files keep their pre-existing permissions.

No new unsafe code, process execution, sockets, unexpected filesystem access,
or build-script behavior was found. Added upstream regression tests were
inspected but not independently executed. This delta audit does not re-audit
unchanged baseline code or certify transitive dependencies.

## Validation

The updated workspace passes 576 tests with 17 intentionally ignored tests.
The local advisory, bans, licenses, and source-policy checks pass. Funded
recovery regressions and native GUI qualification remain separate checks;
this dependency review supplies no funded-chain evidence.
