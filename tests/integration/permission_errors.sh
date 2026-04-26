#!/bin/bash
# tests/integration/permission_errors.sh
# R3.8: Verify that running as unprivileged user produces CAP_BPF message and exit 77.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../../build/kwatch"

echo "[*] Running as unprivileged user (nobody)..."

# Use sudo -u nobody to simulate unprivileged execution.
# Note: redirection of stderr to capture the capability message.
OUT=$(sudo -u nobody $BIN run lo 2>&1 || echo "EXIT_CODE:$?")

if echo "$OUT" | grep -q "EXIT_CODE:77"; then
    echo "[+] Exit code 77 confirmed."
else
    echo "[-] Wrong exit code or no exit code found."
    echo "Output: $OUT"
    exit 1
fi

if echo "$OUT" | grep -qiE "CAP_BPF|CAP_NET_ADMIN|root"; then
    echo "[+] Missing capability/root named in error message."
else
    echo "[-] Error message did not name missing capabilities."
    echo "Output: $OUT"
    exit 1
fi

echo "[+] permission_errors.sh PASS"
exit 0
