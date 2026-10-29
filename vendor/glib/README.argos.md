# Argos GLib safety backport

This directory contains the complete upstream `glib` 0.18.5 crate archive from
<https://static.crates.io/crates/glib/glib-0.18.5.crate>, with its original
manifests and license retained. The archive's SHA-256, verified against
`Cargo.lock` before extraction, is
`233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5`.

The only upstream source changes are the two lines from gtk-rs-core commit
[`b5a4071e439bef2b5eea76c3aa25e5ae84839e34`](https://github.com/gtk-rs/gtk-rs-core/commit/b5a4071e439bef2b5eea76c3aa25e5ae84839e34),
merged in [PR #1343](https://github.com/gtk-rs/gtk-rs-core/pull/1343): declare the
`VariantStrIter::impl_get` output pointer mutable and pass `&mut p` to
`g_variant_get_child`. This repairs
[RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html)
while preserving the GLib 0.18 API required by the GTK3 dependency chain.

The package keeps its upstream version, 0.18.5. Version-based advisory matching
still reports RUSTSEC-2024-0429 for this local package; it cannot recognize a
source backport. Verify these two source changes against the upstream commit and
run `bash scripts/test-glib-backport.sh` from the repository root. That script
runs all three upstream string iterator regressions with optimization, and CI
runs it on Linux. `scripts/fixtures/glib-backport.lock` pins that standalone
test crate's dependencies; workspace builds use the root `Cargo.lock`.
Retire this copy when the GTK dependency chain permits a supported patched
upstream release.
