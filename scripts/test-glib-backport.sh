#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/argos-glib-backport.XXXXXX")
trap 'rm -rf "$test_root"' EXIT

# Cargo cannot run a dependency's unit tests from the consuming workspace.
# Copy only its source outside the workspace to exercise the original upstream
# regressions, including with the optimization that exposed the GLib bug.
cp -R "$repo_root/vendor/glib" "$test_root/glib"
cp "$repo_root/scripts/fixtures/glib-backport.lock" "$test_root/glib/Cargo.lock"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}/glib-backport"
cargo test --locked --manifest-path "$test_root/glib/Cargo.toml" --release --lib \
    test_variant_str_iter -- --nocapture 2>&1 | tee "$test_root/tests.log"

passed=$(grep -cE '^test .*test_variant_str_iter.* \.\.\. ok$' "$test_root/tests.log" || true)
if [ "$passed" -ne 3 ]; then
    echo "Expected all 3 upstream GLib string iterator regressions; saw $passed" >&2
    exit 1
fi
