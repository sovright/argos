#!/usr/bin/env bash
# Explicit phase controller for the independent NU7 profile. No funding, keys,
# public networks, automatic VM startup, or destructive resets.
set -euo pipefail
case "${ARGOS_NU7_PROFILE:-full}" in
    full) readonly URL=http://127.0.0.1:18252; readonly ACTIVATION=32500 ;;
    fast) readonly URL=http://127.0.0.1:18262; readonly ACTIVATION=10 ;;
    *) echo 'ARGOS_NU7_PROFILE must be full or fast' >&2; exit 2 ;;
esac
rpc() {
    curl --fail --silent --show-error --max-time 120 -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" "$URL" \
        | python3 -c 'import json,sys; r=json.load(sys.stdin); assert not r.get("error"),r; print(json.dumps(r["result"]))'
}
height() { rpc getblockcount; }
case "${1:-status}" in
    status) rpc getblockchaininfo; exit 0 ;;
    before) target=$((ACTIVATION - 1)) ;;
    at) target=$ACTIVATION ;;
    after) target=$((ACTIVATION + 1)) ;;
    *) echo 'usage: nu7.sh [status|before|at|after]' >&2; exit 2 ;;
esac
current=$(height)
if ((current > target)); then
    echo "tip $current is already past requested height $target; refusing to rewind/delete state" >&2
    exit 1
fi
while ((current < target)); do
    count=$((target - current)); ((count <= 500)) || count=500
    rpc generate "[$count]" >/dev/null
    next=$(height)
    ((next > current && next <= target)) || { echo "unexpected mining progress $current -> $next" >&2; exit 1; }
    current=$next
    printf '[nu7] height %s / %s\n' "$current" "$target"
done
rpc getblockchaininfo
