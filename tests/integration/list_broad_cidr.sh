#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../../build/kwatch"
IFACE="lo"

cleanup() {
    "$BIN" unblock "$IFACE" 0.0.0.0/0 >/dev/null 2>&1 || true
    kill -TERM "${PID:-0}" 2>/dev/null || true
    wait "${PID:-0}" 2>/dev/null || true
    "$BIN" detach "$IFACE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] Starting kwatch..."
"$BIN" run "$IFACE" > /dev/null 2>&1 &
PID=$!
sleep 2

echo "[*] Blocking broad CIDR..."
"$BIN" block "$IFACE" 0.0.0.0/0

echo "[*] Verifying list output..."
if ! "$BIN" list "$IFACE" | grep -q "^0.0.0.0/0$"; then
    echo "[-] list did not show 0.0.0.0/0"
    exit 1
fi

echo "[+] list_broad_cidr.sh PASS"
