#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../../build/kwatch"
IFACE="veth_host"

$SCRIPT_DIR/../../scripts/netns-veth-setup.sh setup
trap "$SCRIPT_DIR/../../scripts/netns-veth-setup.sh cleanup; kill -TERM ${PID:-0} 2>/dev/null || true; wait ${PID:-0} 2>/dev/null || true" EXIT

echo "[*] Attaching XDP..."
$BIN run $IFACE > /dev/null 2>&1 &
PID=$!
sleep 1

echo "[*] Detaching twice..."
$BIN detach $IFACE
$BIN detach $IFACE

if kill -0 $PID 2>/dev/null; then
    echo "[-] kwatch run process remained alive after detach"
    exit 1
fi

if ip link show $IFACE | grep -q "xdp"; then
    echo "[-] XDP remained attached after repeated detach"
    exit 1
fi

if $BIN stats $IFACE > /dev/null 2>&1; then
    echo "[-] stats still succeeded after detach cleaned up the active owner"
    exit 1
fi

echo "[+] detach_idempotent.sh PASS"
