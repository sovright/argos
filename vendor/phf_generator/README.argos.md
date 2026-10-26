# Argos PHF generator dependency backport

This directory contains the complete upstream `phf_generator` 0.8.0 archive from
<https://static.crates.io/crates/phf_generator/phf_generator-0.8.0.crate>.
The archive's SHA-256, verified against `Cargo.lock` before extraction, is
`17367f0cc86f2d25802b2c26ee58a7b23faeccf78a396094c13dced0d0182526`.
Its upstream package version, MIT license declaration, source, public API, and
hash-generation algorithm are retained.

The only dependency change, reflected in both Cargo manifests, replaces
`rand = { version = "0.7", features = ["small_rng"] }` with
`rand = { version = "0.8.6", features = ["small_rng"], default-features = false }`.
This removes the workspace's remaining Rand 0.7 dependency and uses a release
patched for
[RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097.html).
Disabling Rand's default features is sufficient for this generator's seeded
`SmallRng`; the generator does not use `ThreadRng` or operating-system entropy.

The Rand API calls in `src/lib.rs` are also used by upstream
[`phf_generator` 0.11.3](https://docs.rs/crate/phf_generator/0.11.3/source/src/lib.rs):
`SeedableRng`, `Rng`, `distributions::Standard`, `rngs::SmallRng`, and
`SmallRng::seed_from_u64(FIXED_SEED).sample_iter(Standard)`. That release uses
Rand 0.8 with `small_rng` and no default features. This backport keeps the older
PHF 0.8 hashing and generated-map API required by `selectors` 0.24.

The generated random-key sequence may change with the Rand upgrade, so generated
table bytes need not be identical. Tables must still return the same entries
through their existing PHF lookup API; validate the Tauri/selector builds and
lookups before release. The archive's unused nested `Cargo.lock` is omitted; workspace builds use the
root lockfile. Retire this path patch
when Tauri's dependency chain can use a maintained PHF generator directly.
