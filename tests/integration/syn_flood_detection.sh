#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../../build/kwatch"
IFACE="veth_host"
NS="kwatch_test_ns"

$SCRIPT_DIR/../../scripts/netns-veth-setup.sh setup
trap "$SCRIPT_DIR/../../scripts/netns-veth-setup.sh cleanup; rm -f log.txt" EXIT

echo "[*] Running kwatch with auto-block OFF..."
$BIN --syn-threshold 3 --syn-window 5 run $IFACE 2> log.txt &
PID=$!
sleep 1

echo "[*] Generating fake SYN flood via nping/hping3 (if available) or raw sockets."
# We can simulate this by sending 4 SYNs from different source ports
for i in {1..4}; do
    timeout 1 ip netns exec $NS nc -z -w 1 10.0.0.1 80 >/dev/null 2>&1 || true &
done
echo "[*] Waiting for nc to finish..."
sleep 2

echo "[*] Killing K-Watch (PID $PID)..."
kill -TERM $PID
wait $PID 2>/dev/null || true
echo "[*] K-Watch exited."

if ! grep -q "SYN_FLOOD detected from 10.0.0.2" log.txt; then
    echo "[-] SYN_FLOOD flag not found in logs!"
    cat log.txt
    exit 1
fi

echo "[+] syn_flood_detection.sh PASS"
exit 0