#!/bin/bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$SCRIPT_DIR/../../build/kwatch"
IFACE="lo"

cleanup() {
    if [ -n "${PID:-}" ] && kill -0 "$PID" 2>/dev/null; then
        kill -TERM "$PID" 2>/dev/null || true
        wait "$PID" 2>/dev/null || true
    fi
    rm -f demo-events.log demo-stats.log demo-safety.log
    "$BIN" detach "$IFACE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "[*] Verifying demo safety gate..."
if "$BIN" demo udp-storm --target 8.8.8.8 --duration 1s >/dev/null 2>demo-safety.log; then
    echo "[-] Demo allowed a non-loopback target without override"
    cat demo-safety.log
    exit 1
fi
if ! grep -qi "non-loopback" demo-safety.log; then
    echo "[-] Demo safety error did not mention non-loopback target"
    cat demo-safety.log
    exit 1
fi

echo "[*] Starting kwatch on loopback..."
"$BIN" run "$IFACE" >demo-events.log 2>&1 &
PID=$!
sleep 2

if ! kill -0 "$PID" 2>/dev/null; then
    echo "[-] kwatch run exited before demos ran"
    cat demo-events.log
    exit 1
fi

echo "[*] Generating ICMP proof traffic..."
"$BIN" demo ping-flood --target 127.0.0.1 --duration 2s --rate 20

echo "[*] Generating UDP proof traffic..."
"$BIN" demo udp-storm --target 127.0.0.1 --duration 2s --rate 20

sleep 1
"$BIN" stats "$IFACE" >demo-stats.log

if ! grep -q "ICMP" demo-stats.log; then
    echo "[-] ICMP counter did not appear after ping-flood demo"
    cat demo-stats.log
    exit 1
fi

if ! grep -q "UDP" demo-stats.log; then
    echo "[-] UDP counter did not appear after udp-storm demo"
    cat demo-stats.log
    exit 1
fi

echo "[+] demo_traffic.sh PASS"
