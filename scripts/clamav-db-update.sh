#!/bin/bash
# Update ClamAV signatures via cvdupdate (works when freshclam CDN is blocked)
set -e
if command -v cvdupdate >/dev/null 2>&1; then
    cvd update >>/var/log/clamav-cvdupdate.log 2>&1
    cp -f /root/.cvdupdate/database/*.cvd /var/lib/clamav/ 2>/dev/null || true
    chown clamav:clamav /var/lib/clamav/*.cvd 2>/dev/null || true
    echo "$(date -u) DB updated via cvdupdate" >>/var/log/clamav-cvdupdate.log
elif command -v freshclam >/dev/null 2>&1; then
    freshclam >>/var/log/clamav-cvdupdate.log 2>&1 || true
else
    echo "$(date -u) no update tool found" >>/var/log/clamav-cvdupdate.log
fi
