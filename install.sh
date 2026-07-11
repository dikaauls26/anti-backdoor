#!/bin/bash
# Anti-Backdoor Security Panel — one-shot installer for Ubuntu/Debian
# Usage (server baru):
#   git clone https://github.com/dikaauls26/anti-backdoor.git
#   cd anti-backdoor
#   sudo bash install.sh
set -euo pipefail

PANEL_DIR="/usr/local/maldetect-panel"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="/var/log/anti-backdoor-install.log"
PANEL_PORT=9793

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }
die() { log "ERROR: $*"; exit 1; }

# CyberPanel memakai MariaDB dari repo MariaDB.org. Paket mysql-client (MySQL 8 Ubuntu)
# bentrok dan membuat apt MENGHAPUS mariadb-server — jangan pernah pasang mysql-client di stack ini.
is_cyberpanel() {
    [[ -d /usr/local/CyberCP ]] || [[ -x /usr/local/lscp/bin/lscpd ]] || \
        systemctl list-unit-files lscpd.service 2>/dev/null | grep -qE '^lscpd\.service'
}

mariadb_stack_present() {
    dpkg-query -W -f='${Status}\n' mariadb-server mariadb-client 2>/dev/null | grep -q '^install ok installed'
}

safe_apt_install() {
    local pkgs=("$@")
    [[ ${#pkgs[@]} -gt 0 ]] || return 0
    local sim removed
    sim=$(apt-get -s install -y "${pkgs[@]}" 2>&1 || true)
    removed=$(echo "$sim" | grep '^Remv ' || true)
    if [[ -n "$removed" ]]; then
        log "KONFLIK APT — install ${pkgs[*]} akan menghapus paket:"
        echo "$removed" | tee -a "$LOG"
        if echo "$removed" | grep -qiE 'mariadb|mysql-server|mariadb-server'; then
            die "Instalasi dibatalkan: MariaDB/MySQL server akan ter-uninstall. Lihat $LOG"
        fi
        die "Instalasi dibatalkan karena konflik paket. Lihat $LOG"
    fi
    apt-get install -y -qq "${pkgs[@]}"
}

install_db_client() {
    if is_cyberpanel || mariadb_stack_present; then
        log "CyberPanel/MariaDB terdeteksi — memasang mariadb-client (bukan mysql-client Ubuntu)"
        safe_apt_install mariadb-client
        return
    fi
    log "Memasang klien MySQL/MariaDB..."
    local sim
    sim=$(apt-get -s install -y mysql-client 2>&1 || true)
    if echo "$sim" | grep -qE '^Remv .*mariadb|^Remv .*mysql-server'; then
        log "mysql-client Ubuntu bentrok dengan MariaDB — memakai mariadb-client"
        safe_apt_install mariadb-client
        return
    fi
    safe_apt_install mysql-client
}

verify_database_stack() {
    if ! is_cyberpanel && ! mariadb_stack_present; then
        return 0
    fi
    if systemctl is-active --quiet mariadb 2>/dev/null || systemctl is-active --quiet mysql 2>/dev/null; then
        log "MariaDB/MySQL service: aktif"
        return 0
    fi
    log "PERINGATAN: MariaDB tidak aktif — coba: apt-get install -y mariadb-server mariadb-client && systemctl start mariadb"
}

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

log "=== Anti-Backdoor Panel Installer (one-shot) ==="

log "[1/9] Memperbarui paket APT..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

log "[2/9] Menginstal dependensi..."
BASE_PKGS=(
    git clamav clamav-daemon aide aide-common lynis rkhunter
    python3 python3-pip openssl curl wget tar inotify-tools jq ca-certificates
)
safe_apt_install "${BASE_PKGS[@]}"
for opt in firewalld ufw; do
    apt-get install -y -qq "$opt" >>"$LOG" 2>&1 || log "Peringatan: $opt tidak terpasang (opsional)"
done
install_db_client
verify_database_stack

# rkhunter: allow web-based checks (panel may probe URLs)
if grep -q '^WEB_CMD=' /etc/rkhunter.conf 2>/dev/null; then
    sed -i 's|^WEB_CMD=.*|WEB_CMD=/bin/false|' /etc/rkhunter.conf
fi
rkhunter --propupd >>"$LOG" 2>&1 || true

# --- maldet (Linux Malware Detect) ---
if [[ ! -x /usr/local/sbin/maldet ]]; then
    log "[3/9] Menginstal maldet..."
    TMPD=$(mktemp -d)
    cd "$TMPD"
    wget -q "http://www.rfxn.com/downloads/maldetect-current.tar.gz" -O maldetect.tar.gz
    tar xzf maldetect.tar.gz
    cd maldetect-*
    ./install.sh >>"$LOG" 2>&1
    cd /
    rm -rf "$TMPD"
else
    log "[3/9] maldet sudah terpasang, dilewati"
fi

# --- ClamAV DB via cvdupdate (fallback jika freshclam diblokir CDN) ---
log "[4/9] Menginstal cvdupdate untuk update signature ClamAV..."
pip3 install -q cvdupdate 2>>"$LOG" || pip3 install --break-system-packages -q cvdupdate 2>>"$LOG" || true

install -m 755 "$REPO_DIR/scripts/clamav-db-update.sh" /usr/local/bin/clamav-db-update.sh
/usr/local/bin/clamav-db-update.sh >>"$LOG" 2>&1 || log "Peringatan: update DB ClamAV gagal, coba manual nanti"

# --- Panel files ---
log "[5/9] Menyalin file panel ke $PANEL_DIR..."
mkdir -p "$PANEL_DIR"/{jobs,data,quar_store}
for f in panel.py index.html scanner.py rkscan.py aidescan.py lynisscan.py wpusers.py fileinspect.py imavscan.py quarantine_bulk.py; do
  install -m 644 "$REPO_DIR/panel/$f" "$PANEL_DIR/$f"
done
install -m 755 "$REPO_DIR/scripts/synergy-scan.sh" "$PANEL_DIR/synergy-scan.sh"

# Credentials + web root — pertahankan jika reinstall/update
ADMIN_USER="scanadmin"
ADMIN_PASS=""
KEEP_WEB_ROOTS=""
KEEP_DOMAIN=""
KEEP_ALLOWED=""
if [[ -f "$PANEL_DIR/panel.conf" ]]; then
    # shellcheck source=/dev/null
    . "$PANEL_DIR/panel.conf"
    ADMIN_USER="${USERNAME:-$ADMIN_USER}"
    ADMIN_PASS="${PASSWORD:-}"
    PANEL_PORT="${PORT:-$PANEL_PORT}"
    KEEP_WEB_ROOTS="${WEB_ROOTS:-}"
    KEEP_DOMAIN="${DOMAIN_PATH:-}"
    KEEP_ALLOWED="${ALLOWED_PREFIX:-}"
    log "panel.conf lama ditemukan — kredensial & konfigurasi web root dipertahankan"
fi
if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS=$(openssl rand -base64 18 | tr -dc 'A-Za-z0-9' | head -c 20)
    log "Membuat kredensial panel baru"
fi

# --- Auto-detect layout web root (CyberPanel /home vs custom /var/www) ---
WEB_ROOTS="/home/*/public_html"
DOMAIN_PATH="/home/example.com/public_html"
ALLOWED_PREFIX="/home/,/var/www/,/srv/,/tmp/,/var/tmp/"

detect_web_roots() {
    # 1) CyberPanel style
    if ls -d /home/*/public_html >/dev/null 2>&1; then
        echo "/home/*/public_html"; return
    fi
    # 2) /var/www/<domain>/public_html (custom + subfolder)
    if ls -d /var/www/*/public_html >/dev/null 2>&1; then
        echo "/var/www/*/public_html"; return
    fi
    # 3) /var/www/<domain>/ (folder = domain, web root langsung)
    #    Kecualikan /var/www/html supaya tidak dianggap "domain".
    if ls -d /var/www/*/ >/dev/null 2>&1 && \
       [[ -n "$(ls -d /var/www/*/ 2>/dev/null | grep -v '/var/www/html/' | head -1)" ]]; then
        echo "/var/www/*"; return
    fi
    # 4) single site
    if [[ -d /var/www/html ]]; then
        echo "/var/www/html"; return
    fi
    echo "/home/*/public_html"
}

if [[ -n "$KEEP_WEB_ROOTS" ]]; then
    WEB_ROOTS="$KEEP_WEB_ROOTS"
    log "WEB_ROOTS dipertahankan: $WEB_ROOTS"
else
    WEB_ROOTS="$(detect_web_roots)"
    log "WEB_ROOTS terdeteksi otomatis: $WEB_ROOTS"
fi

if [[ -n "$KEEP_DOMAIN" ]]; then
    DOMAIN_PATH="$KEEP_DOMAIN"
else
    FIRST_WEB=$(ls -d $WEB_ROOTS 2>/dev/null | grep -v '/var/www/html$' | head -1 || true)
    [[ -z "$FIRST_WEB" ]] && FIRST_WEB=$(ls -d $WEB_ROOTS 2>/dev/null | head -1 || true)
    [[ -n "$FIRST_WEB" ]] && DOMAIN_PATH="$FIRST_WEB"
    log "DOMAIN_PATH otomatis: $DOMAIN_PATH"
fi
[[ -n "$KEEP_ALLOWED" ]] && ALLOWED_PREFIX="$KEEP_ALLOWED"

cat >"$PANEL_DIR/panel.conf" <<EOF
USERNAME=$ADMIN_USER
PASSWORD=$ADMIN_PASS
PORT=$PANEL_PORT
DOMAIN_PATH=$DOMAIN_PATH
SCAN_LOG=/root/maldet_scan.log
WEB_ROOTS=$WEB_ROOTS
ALLOWED_PREFIX=$ALLOWED_PREFIX
URL_SCHEME=https
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
for c in cron-rkhunter.sh cron-aide.sh cron-lynis.sh cron-imunify-sync.sh; do
    install -m 755 "$REPO_DIR/scripts/$c" "$PANEL_DIR/$c"
done

# --- ImunifyAV (gratis) + hook ke panel karantina ---
log "[6/9] Menginstal ImunifyAV..."
bash "$REPO_DIR/scripts/install-imunify.sh" >>"$LOG" 2>&1 || log "Peringatan: ImunifyAV gagal — bisa jalankan ulang scripts/install-imunify.sh"

# systemd
log "[7/9] Mengatur service scanpanel..."
install -m 644 "$REPO_DIR/systemd/scanpanel.service" /etc/systemd/system/scanpanel.service
systemctl daemon-reload
systemctl enable scanpanel
systemctl restart scanpanel
sleep 2

# Cron jobs
CRON_MARKER="# anti-backdoor-panel"
(crontab -l 2>/dev/null | grep -v "$CRON_MARKER" || true; cat <<CRON
0 3 * * * $PANEL_DIR/cron-rkhunter.sh $CRON_MARKER
0 4 * * * $PANEL_DIR/cron-aide.sh $CRON_MARKER
0 5 * * 0 $PANEL_DIR/cron-lynis.sh $CRON_MARKER
0 6 * * * /usr/local/bin/clamav-db-update.sh $CRON_MARKER
*/15 * * * * $PANEL_DIR/cron-imunify-sync.sh $CRON_MARKER
CRON
) | crontab -

# Firewall — buka port panel otomatis
log "[8/9] Mengatur firewall port ${PANEL_PORT}/tcp..."
FW_OK=0
if command -v firewall-cmd >/dev/null 2>&1; then
    systemctl enable firewalld 2>/dev/null || true
    systemctl start firewalld 2>/dev/null || true
    IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)
    if [[ -n "$IFACE" ]]; then
        firewall-cmd --permanent --zone=public --add-interface="$IFACE" >>"$LOG" 2>&1 || true
    fi
    firewall-cmd --permanent --zone=public --add-port="${PANEL_PORT}/tcp" >>"$LOG" 2>&1 && FW_OK=1 || true
    firewall-cmd --reload >>"$LOG" 2>&1 || true
fi
if [[ $FW_OK -eq 0 ]] && command -v ufw >/dev/null 2>&1; then
    ufw allow "${PANEL_PORT}/tcp" >>"$LOG" 2>&1 && FW_OK=1 || true
fi
if [[ $FW_OK -eq 1 ]]; then
    log "Firewall: port ${PANEL_PORT}/tcp dibuka"
else
    log "Peringatan: firewall tidak dikonfigurasi otomatis — buka port ${PANEL_PORT}/tcp manual"
fi

# AIDE baseline (lama, di background)
if [[ ! -f /var/lib/aide/aide.db ]]; then
    log "Memulai aideinit di background (30-60 menit)..."
    nohup aideinit >>/var/log/aideinit.log 2>&1 &
else
    log "Database AIDE sudah ada"
fi

# Health check
log "[9/9] Health check panel..."
HEALTH="gagal"
for i in 1 2 3 4 5; do
    if curl -sk -u "${ADMIN_USER}:${ADMIN_PASS}" "https://127.0.0.1:${PANEL_PORT}/api/status" | grep -q clamav_version; then
        HEALTH="ok"
        break
    fi
    sleep 2
done

SERVER_IP=$(curl -fsS --max-time 5 ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')

cat <<BANNER

============================================================
  Anti-Backdoor Panel — instalasi selesai
============================================================

  URL panel : https://${SERVER_IP:-<IP-SERVER>}:${PANEL_PORT}
  Username  : ${ADMIN_USER}
  Password  : ${ADMIN_PASS}

  Simpan kredensial di atas! File: ${PANEL_DIR}/panel.conf

  Service   : systemctl status scanpanel
  Health    : ${HEALTH}
  Log install: ${LOG}

  Server baru — cukup 2 langkah:
    git clone https://github.com/dikaauls26/anti-backdoor.git
    cd anti-backdoor && sudo bash install.sh

  Update panel (server lama):
    bash scripts/deploy-update.sh

  Catatan:
  - Browser akan memperingatkan sertifikat self-signed (normal).
  - AIDE baseline berjalan di background jika belum ada.
  - Setelah aideinit selesai, jalankan "Cek Perubahan File" di panel.

============================================================
BANNER

log "Instalasi selesai (health=${HEALTH})."
[[ "$HEALTH" == "ok" ]] || die "Panel tidak merespons — cek: journalctl -u scanpanel -n 50"
