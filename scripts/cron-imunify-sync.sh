#!/bin/bash
# Sinkronkan temuan ImunifyAV ke panel (setiap 15 menit via cron)
/usr/bin/python3 /usr/local/maldetect-panel/imavscan.py sync >>/var/log/scanpanel-imunify.log 2>&1
