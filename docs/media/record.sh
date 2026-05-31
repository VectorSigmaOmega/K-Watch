#!/bin/bash
# Optional core-scope demo recorder. Not part of the v1.0 PRD gate.
# Requires: asciinema, agg (for SVG generation).

set -euo pipefail

if ! command -v asciinema >/dev/null 2>&1; then
    echo "Error: asciinema not found."
    exit 1
fi

if [ ! -x ./build/kwatch ]; then
    echo "Error: ./build/kwatch not found. Run: cmake --build build"
    exit 1
fi

temp_cast="$(mktemp).cast"

sudo asciinema rec "$temp_cast" --command "bash -c '
    set -e
    echo \"[1] Start K-Watch in NDJSON mode\"
    ./build/kwatch run lo --json &
    KPID=\$!
    trap \"kill -TERM \$KPID 2>/dev/null || true; wait \$KPID 2>/dev/null || true\" EXIT
    sleep 2

    echo \"[2] Generate ICMP proof traffic\"
    ./build/kwatch demo ping-flood --target 127.0.0.1 --duration 2s --rate 20
    sleep 1

    echo \"[3] Generate UDP proof traffic\"
    ./build/kwatch demo udp-storm --target 127.0.0.1 --duration 2s --rate 20
    sleep 1

    echo \"[4] Snapshot counters\"
    ./build/kwatch stats lo
'"

cp "$temp_cast" docs/media/demo.cast

if command -v agg >/dev/null 2>&1; then
    agg "$temp_cast" docs/media/demo.svg
else
    echo "Warning: agg not found; updated docs/media/demo.cast only."
fi
