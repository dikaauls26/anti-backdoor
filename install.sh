#!/bin/bash
# Anti-Backdoor Security Panel — installer for Ubuntu/Debian
# Usage: sudo bash install.sh
set -euo pipefail

PANEL_DIR="/usr/local/maldetect-panel"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="/var/log/anti-backdoor-install.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }
die() { log "ERROR: $*"; exit 1; }

[[ $EUID -eq 0 ]] || die "Jalankan sebagai root: sudo bash install.sh"

if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    case "${ID:-}" in
        ubuntu|debian) log "OS: $PRETTY_NAME" ;;
        *) die "Hanya didukung Ubuntu/Debian (terdeteksi: ${ID:-unknown})" ;;
    esac
else
    die "Tidak bisa mendeteksi OS (/etc/os-release tidak ada)"
fi

log "=== Anti-Backdoor Panel Installer ==="

log "Memperbarui paket APT..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

log "Menginstal dependensi..."
apt-get install -y -qq \
    clamav clamav-daemon \
    aide aide-common \
    lynis rkhunter \
    python3 python3-pip \
    openssl curl wget tar inotify-tools \
    mysql-client \
    ca-certificates

# rkhunter: allow web-based checks (panel may probe URLs)
if grep -q '^WEB_CMD=' /etc/rkhunter.conf 2>/dev/null; then
    sed -i 's|^WEB_CMD=.*|WEB_CMD=/bin/false|' /etc/rkhunter.conf
fi
rkhunter --propupd >>"$LOG" 2>&1 || true

# --- maldet (Linux Malware Detect) ---
if [[ ! -x /usr/local/sbin/maldet ]]; then
    log "Menginstal maldet..."
    TMPD=$(mktemp -d)
    cd "$TMPD"
    wget -q "http://www.rfxn.com/downloads/maldetect-current.tar.gz" -O maldetect.tar.gz
    tar xzf maldetect.tar.gz
    cd maldetect-*
    ./install.sh >>"$LOG" 2>&1
    cd /
    rm -rf "$TMPD"
else
    log "maldet sudah terpasang, dilewati"
fi

# --- ClamAV DB via cvdupdate (fallback jika freshclam diblokir CDN) ---
log "Menginstal cvdupdate untuk update signature ClamAV..."
pip3 install -q cvdupdate 2>>"$LOG" || pip3 install --break-system-packages -q cvdupdate 2>>"$LOG" || true

install -m 755 "$REPO_DIR/scripts/clamav-db-update.sh" /usr/local/bin/clamav-db-update.sh
/usr/local/bin/clamav-db-update.sh >>"$LOG" 2>&1 || log "Peringatan: update DB ClamAV gagal, coba manual nanti"

# --- Panel files ---
log "Menyalin file panel ke $PANEL_DIR..."
mkdir -p "$PANEL_DIR"/{jobs,data,quar_store}
for f in panel.py index.html scanner.py rkscan.py aidescan.py lynisscan.py wpusers.py fileinspect.py; do
  install -m 644 "$REPO_DIR/panel/$f" "$PANEL_DIR/$f"
done

# Credentials
ADMIN_USER="scanadmin"
ADMIN_PASS=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 20)
PANEL_PORT=9793

cat >"$PANEL_DIR/panel.conf" <<EOF
USERNAME=$ADMIN_USER
PASSWORD=$ADMIN_PASS
PORT=$PANEL_PORT
DOMAIN_PATH=/home/example.com/public_html
SCAN_LOG=/root/maldet_scan.log
WEB_ROOTS=/home/*/public_html
EOF
chmod 600 "$PANEL_DIR/panel.conf"

# SSL self-signed
if [[ ! -f "$PANEL_DIR/panel.pem" ]]; then
    log "Membuat sertifikat SSL self-signed..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$PANEL_DIR/panel.pem" -out "$PANEL_DIR/panel.pem" \
        -days 3650 -subj "/CN=scanpanel.local" 2>>"$LOG"
    chmod 600 "$PANEL_DIR/panel.pem"
fi

# Cron scripts
for c in cron-rkhunter.sh cron-aide.sh cron-lynis.sh; do
    install -m 755 "$REPO_DIR/scripts/$c" "$PANEL_DIR/$c"
done

# systemd
install -m 644 "$REPO_DIR/systemd/scanpanel.service" /etc/systemd/system/scanpanel.service
systemctl daemon-reload
systemctl enable scanpanel
systemctl restart scanpanel

# Cron jobs
CRON_MARKER="# anti-backdoor-panel"
(crontab -l 2>/dev/null | grep -v "$CRON_MARKER" || true; cat <<CRON
0 3 * * * $PANEL_DIR/cron-rkhunter.sh $CRON_MARKER
0 4 * * * $PANEL_DIR/cron-aide.sh $CRON_MARKER
0 5 * * 0 $PANEL_DIR/cron-lynis.sh $CRON_MARKER
0 6 * * * /usr/local/bin/clamav-db-update.sh $CRON_MARKER
CRON
) | crontab -

# AIDE baseline (lama, di background)
if [[ ! -f /var/lib/aide/aide.db ]]; then
    log "Memulai aideinit di background (30-60 menit)..."
    nohup aideinit >>/var/log/aideinit.log 2>&1 &
else
    log "Database AIDE sudah ada"
fi

# Firewall hint (optional, tidak diubah otomatis)
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')

cat <<BANNER

============================================================
  Anti-Backdoor Panel — instalasi selesai
============================================================

  URL panel : https://${SERVER_IP:-<IP-SERVER>}:${PANEL_PORT}
  Username  : ${ADMIN_USER}
  Password  : ${ADMIN_PASS}

  Simpan kredensial di atas! File: ${PANEL_DIR}/panel.conf

  Service   : systemctl status scanpanel
  Log install: ${LOG}

  Catatan:
  - Browser akan memperingatkan sertifikat self-signed (normal).
  - AIDE baseline berjalan di background jika belum ada.
  - Setelah aideinit selesai, jalankan "Cek Perubahan File" di panel.
  - Edit DOMAIN_PATH di panel.conf untuk audit user WordPress.

============================================================
BANNER

log "Instalasi selesai."
