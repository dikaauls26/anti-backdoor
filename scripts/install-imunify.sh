#!/bin/bash
# Pasang ImunifyAV (gratis) + hook ke anti-backdoor panel
set -euo pipefail

PANEL_DIR="/usr/local/maldetect-panel"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG="/var/log/anti-backdoor-imunify.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

if [[ ! -f /etc/sysconfig/imunify360/integration.conf ]]; then
    log "Membuat integration.conf untuk standalone/CyberPanel..."
    mkdir -p /var/www/imunifyav-ui/html/imav /etc/sysconfig/imunify360
    cat >/etc/sysconfig/imunify360/integration.conf <<'EOF'
[paths]
ui_path = /var/www/imunifyav-ui/html/imav
ui_path_owner = nobody:nogroup

[pam]
service_name = system-auth

[integration_scripts]
domains = /usr/local/maldetect-panel/imunify-get-domains.sh
EOF
    install -m 755 "$REPO_DIR/scripts/imunify-integration/get-domains.sh" \
        /usr/local/maldetect-panel/imunify-get-domains.sh
fi

if command -v imunify-antivirus >/dev/null 2>&1 || command -v imunify360-agent >/dev/null 2>&1; then
    log "ImunifyAV sudah terpasang"
else
    log "Mengunduh installer ImunifyAV..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq wget ca-certificates

    TMPD=$(mktemp -d)
    wget -q "https://repo.imunify360.cloudlinux.com/defence360/imav-deploy.sh" -O "$TMPD/imav-deploy.sh"
    chmod +x "$TMPD/imav-deploy.sh"
    log "Menjalankan imav-deploy.sh (bisa beberapa menit)..."
    bash "$TMPD/imav-deploy.sh" >>"$LOG" 2>&1 || {
        log "Peringatan: imav-deploy gagal — cek $LOG"
    }
    rm -rf "$TMPD"
fi

BIN=""
for c in imunify-antivirus imunify360-agent; do
    if command -v "$c" >/dev/null 2>&1; then
        BIN="$c"
        break
    fi
done

if [[ -z "$BIN" ]]; then
    log "ERROR: imunify-antivirus tidak ditemukan setelah install"
    exit 1
fi

log "Imunify binary: $BIN ($($BIN version 2>/dev/null | head -1))"

# Standalone / CyberPanel: pastikan agent jalan
systemctl enable imunify-antivirus 2>/dev/null || true
systemctl start imunify-antivirus 2>/dev/null || "$BIN" start 2>/dev/null || true

# Hook malware-detected → panel sync
HOOK_SRC="$REPO_DIR/hooks/malware_detected.py"
HOOK_DST="$PANEL_DIR/hooks/malware_detected.py"
mkdir -p "$PANEL_DIR/hooks"
install -m 755 "$HOOK_SRC" "$HOOK_DST"

if "$BIN" hook list --event malware-detected 2>/dev/null | grep -q malware_detected.py; then
    log "Hook malware-detected sudah terdaftar"
else
    log "Mendaftarkan hook malware-detected..."
    "$BIN" hook add --event malware-detected --path "$HOOK_DST" >>"$LOG" 2>&1 || \
        log "Peringatan: gagal daftar hook (bisa manual lewat Imunify UI)"
fi

# Update signature
"$BIN" update >>"$LOG" 2>&1 || true

python3 "$PANEL_DIR/imavscan.py" sync >>"$LOG" 2>&1 || true
log "ImunifyAV siap — temuan akan muncul di panel tab ImunifyAV"
