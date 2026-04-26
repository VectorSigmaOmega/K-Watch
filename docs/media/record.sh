#!/bin/bash
# docs/media/record.sh
# Requires: asciinema, agg (for SVG generation)

set -e

if ! command -v asciinema &> /dev/null; then
    echo "Error: asciinema not found."
    exit 1
fi

echo "[*] Recording main demo cast..."
# Use a temporary file for the recording
TEMP_CAST=$(mktemp).cast

# Record the sequence:
# 1. Run kwatch run lo --json
# 2. Trigger syn-flood demo
# 3. Show top lo
asciinema rec $TEMP_CAST --command "bash -c 'echo \"[*] Starting kwatch run...\"; timeout 5 ./build/kwatch run lo --json | head -n 5; echo \"[*] Triggering SYN flood demo...\"; sudo ./build/kwatch demo syn-flood --rate 100 --duration 2; echo \"[*] Opening dashboard...\"; timeout 10 sudo ./build/kwatch top lo'"

echo "[*] Generating SVG from cast..."
if command -v agg &> /dev/null; then
    agg $TEMP_CAST docs/media/demo.svg
else
    echo "Warning: agg not found, skipping SVG generation."
    cp $TEMP_CAST docs/media/demo.cast
fi

echo "[+] Done."
