#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../../build/kwatch"
IFACE="veth_host"
NS="kwatch_test_ns"

$SCRIPT_DIR/../../scripts/netns-veth-setup.sh setup
trap "$SCRIPT_DIR/../../scripts/netns-veth-setup.sh cleanup; rm -f stats.log" EXIT

echo "[*] Running kwatch..."
$BIN run $IFACE > /dev/null 2>&1 &
PID=$!
sleep 1

echo "[*] Generating ICMP traffic..."
ip netns exec $NS ping -c 3 10.0.0.1 > /dev/null

echo "[*] Gathering stats..."
$BIN stats $IFACE > stats.log

kill -TERM $PID
wait $PID 2>/dev/null || true

if ! grep -q "ICMP" stats.log; then
    echo "[-] ICMP stats not found!"
    cat stats.log
    exit 1
fi

echo "[+] stats_basic.sh PASS"
exit 0
