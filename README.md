# Anti-Backdoor Security Panel

Panel keamanan web untuk server Linux (Ubuntu/Debian) dengan CyberPanel, OpenLiteSpeed, atau stack serupa. Menggabungkan scan malware website, deteksi backdoor heuristik, karantina, audit user WordPress, dan scan sistem (rkhunter, AIDE, Lynis).

## Fitur

- **Scan website** — heuristik backdoor (`scanner.py`), ClamAV, maldet, deteksi file baru
- **Karantina & restore** — isolasi file mencurigakan + sweep ulang
- **Whitelist** — abaikan false positive
- **Audit user WordPress** — deteksi akun admin mencurigakan
- **Scan sistem** — rkhunter (rootkit), AIDE (integritas file), Lynis (hardening)
- **UI web** — Bootstrap 5, HTTPS, Basic Auth

## Persyaratan

- Ubuntu 20.04+ atau Debian 10+
- Root access
- Minimal 1 GB RAM (AIDE baseline butuh waktu & disk)

## Instalasi cepat

```bash
git clone https://github.com/dikaauls26/anti-backdoor.git
cd anti-backdoor
sudo bash install.sh
```

Installer akan:

1. Memasang ClamAV, maldet, rkhunter, AIDE, Lynis, dan dependensi
2. Mengatur update signature ClamAV via `cvdupdate`
3. Menyalin panel ke `/usr/local/maldetect-panel/`
4. Membuat kredensial acak + sertifikat SSL self-signed
5. Mendaftarkan service `scanpanel` (systemd) dan cron harian

Setelah selesai, buka `https://<IP-SERVER>:9793` di browser.

## Struktur repo

```
anti-backdoor/
├── install.sh              # Installer utama
├── panel/
│   ├── panel.py            # Backend API + HTTPS server
│   ├── index.html          # UI panel
│   ├── scanner.py          # Heuristik backdoor
│   ├── rkscan.py           # Parser rkhunter
│   ├── aidescan.py         # Parser AIDE
│   ├── lynisscan.py        # Parser Lynis
│   ├── wpusers.py          # Audit user WordPress
│   ├── fileinspect.py      # Detail file + probe URL
│   └── panel.conf.example  # Contoh konfigurasi
├── scripts/
│   ├── clamav-db-update.sh
│   ├── cron-rkhunter.sh
│   ├── cron-aide.sh
│   └── cron-lynis.sh
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
| `WEB_ROOTS` | Glob path website (default `/home/*/public_html`) |
| `DOMAIN_PATH` | Path default untuk audit WP user |
| `SCAN_LOG` | Log scan maldet |

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

## Keamanan

- Jangan commit `panel.conf` atau `panel.pem` ke git
- Ganti password default setelah instalasi
- Batasi port 9793 di firewall hanya untuk IP admin
- Sertifikat self-signed — gunakan reverse proxy + Let's Encrypt jika perlu

## Lisensi

MIT — gunakan dan modifikasi sesuai kebutuhan.
