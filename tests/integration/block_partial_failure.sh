#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../../build/kwatch"
IFACE="lo"

cleanup() {
    kill -TERM "${PID:-0}" 2>/dev/null || true
    wait "${PID:-0}" 2>/dev/null || true
    "$BIN" detach "$IFACE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] Starting kwatch..."
$BIN run $IFACE > /dev/null 2>&1 &
PID=$!
sleep 2

echo "[*] Exercising multi-CIDR partial failure..."
set +e
$BIN block "$IFACE" 127.0.0.1/32 bad.ip > /dev/null 2> block.log
status=$?
set -e

if [ "$status" -ne 65 ]; then
    echo "[-] block did not return 65 for partial failure"
    cat block.log
    exit 1
fi

if ! $BIN list "$IFACE" | grep -q "127.0.0.1/32"; then
    echo "[-] valid CIDR was not applied before the partial failure"
    exit 1
fi

echo "[+] block_partial_failure.sh PASS"
