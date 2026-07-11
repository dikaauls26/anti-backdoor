# NOTES — Anti-Backdoor Security Stack v5

Dokumentasi singkat arsitektur **mixing antivirus** di server Ubuntu/CyberPanel.

## Konsep: Scan ImunifyAV, Karantina via Panel

ImunifyAV (gratis) sejak **v6.2** tidak lagi punya tombol **Quarantine** / **Delete** di UI maupun CLI ([rilis CloudLinux](https://blog.imunify360.com/release-notes-imunifyav-v.6.2)). Hanya mendeteksi.

Panel anti-backdoor mengisi celah itu:

```
ImunifyAV scan  →  temuan masuk tab "ImunifyAV"
                         ↓
              Tombol Karantina (panel)
                         ↓
         File dipindah ke quar_store + chmod 0
         + dihapus dari Imunify malicious list
```

## Engine yang saling bersinergi

| Engine | Peran | Auto-clean? |
|--------|-------|-------------|
| **ImunifyAV** | Signature CloudLinux, scan on-demand | ❌ (gratis) |
| **ClamAV** | Signature open-source | Scan only |
| **maldet** | RFXN webshell signatures | Scan only |
| **Heuristik backdoor** | eval/exec/base64 di PHP | Deteksi only |
| **rkhunter** | Rootkit / backdoor OS | Deteksi only |
| **AIDE** | Integritas file sistem | Deteksi only |
| **Lynis** | Audit hardening | Saran only |
| **Panel Karantina** | Isolasi file berbahaya | ✅ Manual 1-klik |

## CyberPanel: jangan uninstall MariaDB

`install.sh` versi lama memasang paket Ubuntu `mysql-client`. Di server CyberPanel
(MariaDB dari repo MariaDB.org), APT menganggap itu konflik dan **menghapus**
`mariadb-server`, `mariadb-client`, dan `mariadb-client-core` saat install.

Log apt tipikal:

```
Commandline: apt-get install ... mysql-client ...
Remove: mariadb-server, mariadb-client-core, mariadb-client
```

Perbaikan (sudah di `install.sh`):

1. Deteksi CyberPanel (`/usr/local/CyberCP`, service `lscpd`) atau paket MariaDB terpasang
2. Pasang `mariadb-client` — **bukan** `mysql-client` Ubuntu
3. `safe_apt_install`: jalankan `apt-get -s` dulu; batalkan jika ada baris `Remv` yang
   menyentuh mariadb/mysql-server

Data di `/var/lib/mysql` biasanya masih utuh setelah uninstall paket; cukup reinstall
`mariadb-server mariadb-client` lalu start service.

## Scan Sinergi (disarankan)

Jalankan dari panel → **Scan Sinergi** atau CLI:

```bash
/usr/local/maldetect-panel/synergy-scan.sh /home/domain.com/public_html 8
```

Urutan:
1. ImunifyAV on-demand + sync malicious list
2. maldet `-a`
3. clamscan recursive
4. Heuristik backdoor (`scanner.py`)

Semua temuan dikumpulkan di **Temuan Virus** (tab terpisah per engine).

## ImunifyAV — perintah CLI

```bash
# Scan satu domain
imunify-antivirus malware on-demand start --path /home/user/public_html

# Scan semua user
imunify-antivirus malware user scan

# Lihat temuan
imunify-antivirus malware malicious list --limit 500

# Sync ke panel (otomatis tiap 15 menit via cron)
python3 /usr/local/maldetect-panel/imavscan.py sync
```

## Karantina dari temuan ImunifyAV

1. Buka panel → **Temuan Virus** → tab **ImunifyAV**
2. Klik **Karantina** pada file yang ingin diisolasi
3. Panel akan:
   - Memindah file ke `/usr/local/maldetect-panel/quar_store/`
   - Mencatat di `data/quarantine.json`
   - Menjalankan `imavscan.py remove-listed` agar hilang dari daftar Imunify

## Hook otomatis

Saat Imunify mendeteksi malware real-time:

```
Event malware-detected → hooks/malware_detected.py → imavscan.py sync
```

Hook terdaftar via `install-imunify.sh`.

## Cron otomatis

| Waktu | Tugas |
|-------|-------|
| Setiap 15 menit | Sync Imunify malicious list |
| 03:00 | rkhunter |
| 04:00 | AIDE |
| 05:00 Minggu | Lynis |
| 06:00 | Update ClamAV DB |

## Update dari Git

```bash
cd /root/anti-backdoor   # atau path clone Anda
git pull origin main
sudo bash install.sh     # idempotent — update file panel + Imunify hook
sudo systemctl restart scanpanel
```

Atau update ringan tanpa reinstall penuh:

```bash
git pull origin main
sudo cp panel/* /usr/local/maldetect-panel/
sudo cp scripts/synergy-scan.sh /usr/local/maldetect-panel/
sudo systemctl restart scanpanel
python3 /usr/local/maldetect-panel/imavscan.py sync
```

## Server: 172.236.142.200

- OS: Ubuntu 24.04, CyberPanel + OpenLiteSpeed
- ClamAV terpasang (Juni 2026)
- Backdoor GSocket `/usr/bin/defunct` pernah ditemukan & dikarantina
- Panel: `https://<IP>:9793`

## Catatan keamanan

- Ganti password root & panel setelah instalasi
- ImunifyAV gratis ≠ ImunifyAV+ (yang punya auto-cleanup berbayar)
- Karantina panel **bukan** pengganti reinstall jika server fully compromised (backdoor level sistem)
