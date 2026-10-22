#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s PACKAGE FULL_TEST_NAME\n' "$0" >&2
  exit 2
fi

test_output=$(mktemp)
trap 'rm -f "$test_output"' EXIT
cargo test --color never -p "$1" "$2" -- --exact 2>&1 | tee "$test_output"
if ! grep -Eq '^test result: ok\. [1-9][0-9]* passed;' "$test_output"; then
  printf "Exact Cargo test '%s' in package '%s' ran zero tests.\n" "$2" "$1" >&2
  exit 1
fi
