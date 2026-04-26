#!/bin/bash
# docs/media/record.sh
# Requires: asciinema, agg (for SVG generation)

set -e

if ! command -v asciinema &> /dev/null; then
    echo "Error: asciinema not found."
    exit 1
fi

echo "[*] Recording main demo cast..."
TEMP_CAST=$(mktemp).cast

# Record the sequence. We run the ENTIRE sequence under a single bash -c.
# R6.2 Story: (a) kwatch run lo --json; (b) trigger syn-flood demo; (c) cut to top lo.
# Note: we use timeout to keep the recording length (R6.2: 25-45s).
# We use sudo here so the internal commands don't prompt for passwords.
sudo asciinema rec $TEMP_CAST --command "bash -c '
    echo \"[Phase 1] Starting kwatch run --json (Audience B view)...\"
    ./build/kwatch run lo --json & 
    KPID=\$!
    sleep 3
    echo \"[Phase 2] Triggering SYN flood demo...\"
    ./build/kwatch demo syn-flood --rate 50 --duration 2
    sleep 2
    kill \$KPID
    
    echo \"[Phase 3] Opening Dashboard (kwatch top)...\"
    timeout 10 ./build/kwatch top lo
'"

echo "[*] Generating SVG from cast..."
if command -v agg &> /dev/null; then
    agg $TEMP_CAST docs/media/demo.svg
else
    echo "Warning: agg not found, copying cast to docs/media/demo.cast."
    cp $TEMP_CAST docs/media/demo.cast
fi

# Create a secondary cast for top cycling (R6.5)
echo "[*] Recording top view cycling..."
TOP_CAST=$(mktemp).cast
sudo asciinema rec $TOP_CAST --command "timeout 8 ./build/kwatch top lo"
cp $TOP_CAST docs/media/top.cast

echo "[+] Done."
