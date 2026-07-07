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

## Instalasi cepat

```bash
git clone https://github.com/dikaauls26/anti-backdoor.git
cd anti-backdoor
sudo bash install.sh
```

Installer akan:

1. Memasang ClamAV, maldet, rkhunter, AIDE, Lynis, **ImunifyAV**, dan dependensi
2. Mengatur update signature ClamAV via `cvdupdate`
3. Mendaftarkan hook ImunifyAV → panel karantina
4. Menyalin panel ke `/usr/local/maldetect-panel/`
5. Membuat kredensial acak + sertifikat SSL self-signed
6. Mendaftarkan service `scanpanel` (systemd) dan cron harian + sync Imunify 15 menit

Setelah selesai, buka `https://<IP-SERVER>:9793` di browser.

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
| Setiap 15 menit | Sync ImunifyAV malicious list |

Lihat [NOTES.md](NOTES.md) untuk arsitektur mixing ImunifyAV + karantina panel.

## Keamanan

- Jangan commit `panel.conf` atau `panel.pem` ke git
- Ganti password default setelah instalasi
- Batasi port 9793 di firewall hanya untuk IP admin
- Sertifikat self-signed — gunakan reverse proxy + Let's Encrypt jika perlu

## Lisensi

MIT — gunakan dan modifikasi sesuai kebutuhan.
