#!/usr/bin/env bash
set -euo pipefail

if [[ $# -eq 0 ]]; then
  printf 'usage: %s PACKAGE...\n' "$0" >&2
  exit 2
fi

# GitHub's Ubuntu runners route their signed Ubuntu sources through this
# mirror list. Prefer the Ubuntu archive after observed slow Azure downloads,
# retaining the runner's other mirrors as fallbacks. Older/different layouts
# keep their existing sources and still receive the bounded acquire options.
if [[ -f /etc/apt/apt-mirrors.txt ]]; then
  printf '%s\t%s\n' \
    'https://archive.ubuntu.com/ubuntu/' 'priority:1' \
    'http://azure.archive.ubuntu.com/ubuntu/' 'priority:2' \
    'https://security.ubuntu.com/ubuntu/' 'priority:3' \
    | sudo tee /etc/apt/apt-mirrors.txt
else
  printf 'Runner apt mirror list absent; retaining configured sources.\n'
fi

apt_options=(
  -o Acquire::Retries=2
  -o Acquire::http::Timeout=30
  -o Acquire::https::Timeout=30
)
sudo apt-get "${apt_options[@]}" update
sudo apt-get "${apt_options[@]}" install -y "$@"
