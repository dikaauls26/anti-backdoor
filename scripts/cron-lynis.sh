#!/bin/bash
/usr/bin/python3 /usr/local/maldetect-panel/lynisscan.py audit >>/var/log/scanpanel-lynis.log 2>&1
