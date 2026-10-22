#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

docs=(
  README.md
  docs/THREAT_MODEL.md
  docs/secret-memory-evaluation.md
  gui/src/index.html
)

fail() {
  printf 'secret-lifecycle docs check: %s\n' "$*" >&2
  exit 1
}

require() {
  local pattern=$1
  local file=$2
  local description=$3
  rg -qi -- "$pattern" "$file" || fail "$file is missing $description"
}

reject() {
  local pattern=$1
  local description=$2
  if rg -ni -- "$pattern" "${docs[@]}"; then
    fail "found stale $description language"
  fi
}

reject 'private on Unix' 'Unix-only privacy'
reject 'remove(d|s) (it )?after a successful sweep' 'success-implies-cleanup'
reject 'Delete remaining recovery state only after confirming the funds arrived' 'arrival-authorizes-manual-deletion'

# User-facing cleanup claims must name the whole conservative decision, rather
# than reducing it to a broadcast result or one confirmation.
require 'canonical mined' README.md 'canonical-mined cleanup rule'
require 'two .*reconciliation rounds' README.md 'two-round cleanup rule'
require 'two independent (operator )?authorit|two independent operators' README.md 'independent observation authorities'
require '100[- ]block|depth (of )?100' README.md '100-block reorg window'
require 'manifest' README.md 'checkpoint manifest authority'
require 'checkpoint generation|exact generation' README.md 'exact checkpoint generation binding'
for state in prepared unknown pending contested rejected expired; do
  require "$state" README.md "retained $state lifecycle state"
done

# The reviewer-facing model must spell out platform policy and source binding.
require '0700' docs/THREAT_MODEL.md 'Unix private-directory mode'
require '0600' docs/THREAT_MODEL.md 'Unix private-file mode'
require 'Windows DACL' docs/THREAT_MODEL.md 'Windows DACL policy'
require 'owner.*LocalSystem|LocalSystem.*owner' docs/THREAT_MODEL.md 'owner and LocalSystem ACL principals'
require 'reused (objects|files|directories)' docs/THREAT_MODEL.md 'reused-object hardening'
require 'source snapshot|wallet snapshot' docs/THREAT_MODEL.md 'backend wallet snapshot identity'
require 'review ID' docs/THREAT_MODEL.md 'opaque review identity'
require 'changed since review' docs/THREAT_MODEL.md 'changed-source refusal'
require 're-deriv|recovered key.*address|address.*recovered key' docs/THREAT_MODEL.md 'runtime recovered-key validation'

# The memory evaluation must describe what the implementation does and does
# not promise; zeroization is deliberately best effort.
require 'best-effort zeroization' docs/secret-memory-evaluation.md 'best-effort zeroization scope'
require 'swap' docs/secret-memory-evaluation.md 'swap limitation'
require 'core dump|crash dump' docs/secret-memory-evaluation.md 'dump limitation'
require 'allocator' docs/secret-memory-evaluation.md 'allocator-copy limitation'
require 'kernel cache' docs/secret-memory-evaluation.md 'kernel-cache limitation'
require 'compromised|live memory' docs/secret-memory-evaluation.md 'live-process threat'
require 'process' docs/secret-memory-evaluation.md 'live-process limitation'

# GUI help must expose source invalidation, clear points, and conservative
# checkpoint retention without claiming the browser can guarantee erasure.
require 'changed since review' gui/src/index.html 'wallet review invalidation message'
require 'Start over|navigation|cancel' gui/src/index.html 'secret-clearing exits'
for state in prepared unknown pending contested rejected expired; do
  require "$state" gui/src/index.html "retained $state lifecycle state"
done
require 'two newest' gui/src/index.html 'newest-round cleanup requirement'
require 'same mined height and block hash|same block height and hash' gui/src/index.html 'same-block cleanup requirement'
require 'current checkpoint notes.*equal.*durable manifest' gui/src/index.html 'current-note manifest equality gate'
require 'best-effort zeroization' gui/src/index.html 'zeroization limitation'

printf 'secret-lifecycle docs check: ok\n'
