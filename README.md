# Anti-Backdoor Security Panel

Panel keamanan web untuk server Linux (Ubuntu/Debian) dengan CyberPanel, OpenLiteSpeed, atau stack serupa. Menggabungkan **ImunifyAV**, ClamAV, maldet, scan malware website, deteksi backdoor heuristik, **karantina manual** (menggantikan auto-clean Imunify gratis), audit user WordPress, dan scan sistem (rkhunter, AIDE, Lynis).

## Fitur

- **ImunifyAV** — scan signature CloudLinux; temuan + tombol **Karantina** di panel (karena Imunify gratis tidak auto-clean sejak v6.2)
- **Scan Sinergi** — ImunifyAV + maldet + ClamAV + heuristik backdoor dalam satu job
- **Scan website** — heuristik backdoor (`scanner.py`), ClamAV, maldet, deteksi file baru
- **Karantina & restore** — isolasi file mencurigakan + sweep ulang + sync Imunify malicious list
- **Whitelist** — abaikan false positive
- **Audit user WordPress** — deteksi akun admin mencurigakan
- **Scan sistem** — rkhunter (rootkit), AIDE (integritas file), Lynis (hardening)
- **UI web** — Bootstrap 5, HTTPS, Basic Auth

## Persyaratan

- Ubuntu 20.04+ atau Debian 10+
- Root access
- Minimal 1 GB RAM (AIDE baseline butuh waktu & disk)

## Instalasi cepat (server baru — 1x run)

```bash
git clone https://github.com/dikaauls26/anti-backdoor.git
cd anti-backdoor
sudo bash install.sh
```

Itu saja. `install.sh` otomatis menjalankan semuanya:

1. Install dependensi (ClamAV, maldet, rkhunter, AIDE, Lynis, ImunifyAV, git, dll.)
2. Update signature ClamAV via `cvdupdate`
3. Deploy panel ke `/usr/local/maldetect-panel/`
4. Buat kredensial acak + SSL self-signed
5. Register service `scanpanel` (systemd) + cron harian
6. Buka firewall port **9793/tcp** (firewalld/ufw)
7. Auto-detect `DOMAIN_PATH` dari `/home/*/public_html` pertama
8. Health check API panel

Di akhir install, username/password ditampilkan di terminal. Buka `https://<IP-SERVER>:9793`.

### Update panel (server yang sudah terpasang)

```bash
cd /root/anti-backdoor   # atau path clone kamu
sudo bash scripts/deploy-update.sh
```

Kredensial lama dipertahankan saat reinstall/update.

## Struktur repo

```
anti-backdoor/
├── install.sh              # Installer utama
├── NOTES.md                # Dokumentasi arsitektur mixing antivirus
├── panel/
│   ├── panel.py            # Backend API + HTTPS server
│   ├── imavscan.py         # Bridge ImunifyAV ↔ karantina panel
│   ├── index.html          # UI panel
│   └── ...
├── hooks/
│   └── malware_detected.py # Hook ImunifyAV real-time
├── scripts/
│   ├── install-imunify.sh  # Pasang ImunifyAV + hook
│   ├── synergy-scan.sh     # Scan semua engine sekaligus
│   ├── cron-imunify-sync.sh
│   └── ...
└── systemd/
    └── scanpanel.service
```

## Konfigurasi

Salin contoh konfigurasi dan sesuaikan:

```bash
cp /usr/local/maldetect-panel/panel.conf.example /usr/local/maldetect-panel/panel.conf
nano /usr/local/maldetect-panel/panel.conf
systemctl restart scanpanel
```

| Key | Deskripsi |
|-----|-----------|
| `USERNAME` | Login panel |
| `PASSWORD` | Password panel |
| `PORT` | Port HTTPS (default 9793) |
| `WEB_ROOTS` | Glob path website (comma-separated). Lihat tabel layout di bawah |
| `DOMAIN_PATH` | Path default untuk audit WP user |
| `ALLOWED_PREFIX` | Prefix path yang boleh dikarantina/diinspeksi (comma-separated) |
| `URL_SCHEME` | `http`/`https` untuk fitur Test URL |
| `SCAN_LOG` | Log scan maldet |

### Layout web root (server non-CyberPanel / custom)

`install.sh` mendeteksi otomatis, tapi bisa di-set manual di `panel.conf`:

| Layout server | `WEB_ROOTS` |
|---------------|-------------|
| CyberPanel | `/home/*/public_html` |
| Custom `/var/www/<domain>/` (folder = domain) | `/var/www/*` |
| Custom `/var/www/<domain>/public_html` | `/var/www/*/public_html` |
| Single site | `/var/www/html` |
| Gabungan | `/home/*/public_html,/var/www/*` |

Setelah ubah, jalankan `systemctl restart scanpanel`. Panel akan auto-scan semua
folder yang cocok saat memilih domain **"— Semua domain —"**, dan tetap bisa pilih
per-domain dari dropdown.

## Perintah berguna

```bash
# Status service
systemctl status scanpanel

# Restart panel
systemctl restart scanpanel

# Update signature ClamAV manual
/usr/local/bin/clamav-db-update.sh

# Scan rkhunter manual
python3 /usr/local/maldetect-panel/rkscan.py check

# Cek AIDE manual
python3 /usr/local/maldetect-panel/aidescan.py check

# Audit Lynis manual
python3 /usr/local/maldetect-panel/lynisscan.py audit
```

## Cron (otomatis oleh install.sh)

| Waktu | Tugas |
|-------|-------|
| 03:00 harian | rkhunter |
| 04:00 harian | AIDE |
| 05:00 Minggu | Lynis |
| 06:00 harian | Update ClamAV DB |
| Setiap 15 menit | Sync ImunifyAV malicious list |

Lihat [NOTES.md](NOTES.md) untuk arsitektur mixing ImunifyAV + karantina panel.

## Keamanan

- Jangan commit `panel.conf` atau `panel.pem` ke git
- Ganti password default setelah instalasi
- Batasi port 9793 di firewall hanya untuk IP admin
- Sertifikat self-signed — gunakan reverse proxy + Let's Encrypt jika perlu

## CyberPanel / MariaDB

**Penting:** Jangan pasang `mysql-client` dari repo Ubuntu di server CyberPanel — APT akan
**menghapus `mariadb-server`** karena konflik paket. Installer v2+ mendeteksi CyberPanel
otomatis dan memakai `mariadb-client` saja, plus simulasi `apt-get -s` sebelum install agar
tidak ada paket database yang ter-uninstall tanpa sengaja.

Jika MariaDB sudah terhapus karena versi lama installer:

```bash
apt-get install -y mariadb-server mariadb-client
systemctl start mariadb
mysql -e "SHOW DATABASES;"
```

## Lisensi

MIT — gunakan dan modifikasi sesuai kebutuhan.
