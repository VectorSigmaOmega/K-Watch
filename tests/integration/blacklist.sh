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

echo "[*] Blocking 10.0.0.2..."
$BIN block $IFACE 10.0.0.2/32

echo "[*] Generating ICMP traffic from 10.0.0.2 (should be dropped)..."
ip netns exec $NS ping -c 3 -W 1 10.0.0.1 > /dev/null 2>&1 || true

echo "[*] Unblocking 10.0.0.2..."
$BIN unblock $IFACE 10.0.0.2/32

echo "[*] Generating ICMP traffic from 10.0.0.2 (should pass)..."
ip netns exec $NS ping -c 3 10.0.0.1 > /dev/null

echo "[*] Checking drops..."
$BIN stats $IFACE > stats.log

kill -TERM $PID
wait $PID 2>/dev/null || true

if ! grep -q "DROPPED" stats.log; then
    echo "[-] No DROPPED packets recorded!"
    cat stats.log
    exit 1
fi

echo "[+] blacklist.sh PASS"
exit 0