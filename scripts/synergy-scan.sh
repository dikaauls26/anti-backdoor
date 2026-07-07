#!/bin/bash
# Scan sinergi: ImunifyAV + maldet + ClamAV + heuristik backdoor untuk satu path
set -euo pipefail

PANEL="/usr/local/maldetect-panel"
TARGET="${1:-}"
THRESH="${2:-8}"

if [[ -z "$TARGET" ]]; then
    echo "Usage: synergy-scan.sh /home/domain/public_html [threshold]"
    exit 1
fi

if [[ ! -d "$TARGET" ]]; then
    echo "ERROR: path tidak ada: $TARGET"
    exit 1
fi

echo "=== [1/4] ImunifyAV on-demand ==="
python3 "$PANEL/imavscan.py" scan "$TARGET" || true

echo "=== [2/4] maldet ==="
/usr/local/sbin/maldet -a "$TARGET" || true

echo "=== [3/4] ClamAV ==="
clamscan -r "$TARGET" --infected -i || true

echo "=== [4/4] Heuristik backdoor ==="
python3 "$PANEL/scanner.py" backdoor "$THRESH" "$TARGET" || true

echo "=== Sync Imunify malicious list ==="
python3 "$PANEL/imavscan.py" sync || true

echo "=== Selesai — buka panel Temuan Virus untuk karantina ==="
