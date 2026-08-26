# Fuzzing the BDB walker

`bdb.rs` parses attacker-controlled bytes, so it is fuzzed rather than only
unit-tested. Any panic, OOM, or hang is a real finding.

    cargo +nightly fuzz run bdb_walk -- -max_total_time=300

The corpus is seeded from the golden wallet fixtures in
`../tests/fixtures/`. When the fuzzer finds a crash, add the input as a
regression test in `src/bdb.rs` before fixing the bug, so it stays covered.

Not run in CI: it needs a nightly toolchain and is time-bounded rather than
pass/fail. Run it locally before merging changes to `bdb.rs`.
