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

echo "[*] Stopping kwatch..."
kill -TERM $PID
wait $PID
PID=""

echo "[*] Verifying no-active-map failures..."
if "$BIN" stats "$IFACE" > /dev/null 2>&1; then
    echo "[-] stats succeeded without an active owner"
    exit 1
fi
if "$BIN" list "$IFACE" > /dev/null 2>&1; then
    echo "[-] list succeeded without an active owner"
    exit 1
fi
if "$BIN" block "$IFACE" 127.0.0.1/32 > /dev/null 2>&1; then
    echo "[-] block succeeded without an active owner"
    exit 1
fi
if "$BIN" unblock "$IFACE" 127.0.0.1/32 > /dev/null 2>&1; then
    echo "[-] unblock succeeded without an active owner"
    exit 1
fi

echo "[+] no_active_maps.sh PASS"
