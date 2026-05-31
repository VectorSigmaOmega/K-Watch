#!/bin/bash
# tests/integration/permission_errors.sh
# R3.8: Verify that running as unprivileged user produces CAP_BPF message and exit 77.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../../build/kwatch"
TMPDIR="$(mktemp -d /tmp/kwatch-permission.XXXXXX)"
trap 'rm -rf "$TMPDIR"' EXIT
TEST_BIN="$TMPDIR/kwatch"

echo "[*] Running as unprivileged user (nobody)..."

# nobody cannot necessarily traverse the developer workspace under /home.
chmod 755 "$TMPDIR"
cp "$BIN" "$TEST_BIN"
chmod 755 "$TEST_BIN"

# Use sudo -u nobody to simulate unprivileged execution.
# Note: redirection of stderr to capture the capability message.
OUT=$(sudo -u nobody "$TEST_BIN" run lo 2>&1 || echo "EXIT_CODE:$?")

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

echo "[*] Running demo as unprivileged user (nobody)..."
OUT_DEMO=$(sudo -u nobody "$TEST_BIN" demo ping-flood --target 127.0.0.1 --duration 1s --rate 1 2>&1 || echo "EXIT_CODE:$?")

if echo "$OUT_DEMO" | grep -q "EXIT_CODE:77"; then
    echo "[+] Demo exit code 77 confirmed."
else
    echo "[-] Wrong demo exit code or no exit code found."
    echo "Output: $OUT_DEMO"
    exit 1
fi

if echo "$OUT_DEMO" | grep -qiE "CAP_NET_RAW|root"; then
    echo "[+] Demo permission message named required privilege."
else
    echo "[-] Demo permission message did not name required privilege."
    echo "Output: $OUT_DEMO"
    exit 1
fi

echo "[+] permission_errors.sh PASS"
exit 0
