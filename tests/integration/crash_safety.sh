#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../../build/kwatch"
IFACE="veth_host"

$SCRIPT_DIR/../../scripts/netns-veth-setup.sh setup
trap "$SCRIPT_DIR/../../scripts/netns-veth-setup.sh cleanup" EXIT

echo "[*] Attaching XDP..."
$BIN run $IFACE > /dev/null 2>&1 &
PID=$!
sleep 1

if ! ip link show $IFACE | grep -q "xdp"; then
    echo "[-] Failed to attach XDP"
    kill -9 $PID
    exit 1
fi

echo "[*] Killing process with SIGKILL..."
kill -KILL $PID
wait $PID 2>/dev/null || true

if ip link show $IFACE | grep -q "xdp"; then
    echo "[-] XDP remained attached after SIGKILL!"
    exit 1
fi

if $BIN stats $IFACE > /dev/null 2>&1; then
    echo "[-] stats still succeeded after abrupt process death"
    exit 1
fi

echo "[+] crash_safety.sh PASS"
exit 0
