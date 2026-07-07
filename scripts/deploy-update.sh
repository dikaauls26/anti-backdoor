#!/bin/bash
# Update panel dari git (jalankan di server sebagai root)
set -euo pipefail

INSTALL_DIR="${1:-/root/anti-backdoor}"
PANEL_DIR="/usr/local/maldetect-panel"

if [[ ! -d "$INSTALL_DIR/.git" ]]; then
    echo "Clone repo..."
    git clone https://github.com/dikaauls26/anti-backdoor.git "$INSTALL_DIR"
fi

cd "$INSTALL_DIR"
git pull origin main

echo "=== Update panel files ==="
bash install.sh

echo "=== Restart scanpanel ==="
systemctl restart scanpanel

echo "=== Sync ImunifyAV ==="
python3 "$PANEL_DIR/imavscan.py" sync 2>/dev/null || bash scripts/install-imunify.sh

echo "Done. Panel: https://$(hostname -I | awk '{print $1}'):9793"
