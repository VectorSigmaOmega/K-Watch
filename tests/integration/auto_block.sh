#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../../build/kwatch"
IFACE="veth_host"
NS="kwatch_test_ns"

$SCRIPT_DIR/../../scripts/netns-veth-setup.sh setup
trap "$SCRIPT_DIR/../../scripts/netns-veth-setup.sh cleanup; rm -f log.txt stats.log" EXIT

echo "[*] Running kwatch with auto-block ON..."
$BIN --syn-threshold 3 --syn-window 5 --auto-block run $IFACE 2> log.txt &
PID=$!
sleep 1

# Generate 4 SYNs
echo "[*] Generating SYNs..."
for i in {1..4}; do
    timeout 1 ip netns exec $NS nc -z -w 1 10.0.0.1 80 >/dev/null 2>&1 || true &
done
echo "[*] Waiting for nc to finish..."
sleep 2

if ! grep -q "Auto-blocked IP: 10.0.0.2" log.txt; then
    echo "[-] Auto-block event not found in logs!"
    cat log.txt
    kill -TERM $PID
    exit 1
fi

echo "[*] Checking if IP is actually blocked..."
$BIN list $IFACE > stats.log

echo "[*] Killing K-Watch (PID $PID)..."
kill -TERM $PID
wait $PID 2>/dev/null || true
echo "[*] K-Watch exited."

if ! grep -q "10.0.0.2/32" stats.log; then
    echo "[-] 10.0.0.2 is not in the blacklist!"
    cat stats.log
    exit 1
fi

echo "[+] auto_block.sh PASS"
exit 0