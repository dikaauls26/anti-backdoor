#!/usr/bin/env python3
"""AIDE file integrity check for security panel.

Usage:
  aidescan.py check   -> bandingkan filesystem vs baseline, tulis aide_latest.json
  aidescan.py init    -> buat/perbarui baseline (aideinit)
"""
import os
import re
import sys
import json
import time
import subprocess

BASE = "/usr/local/maldetect-panel"
DATA = os.path.join(BASE, "data")
OUT = os.path.join(DATA, "aide_latest.json")
LOG = "/var/log/aide/aide.log"

# Perubahan normal di server web — kurangi noise.
BENIGN_PATTERNS = [
    r"/var/log/", r"/var/lib/aide/", r"/tmp/", r"/run/",
    r"\.log$", r"\.pid$", r"/dev/shm/",
    r"lastrun", r"utmp", r"wtmp", r"journal",
]


def is_benign(path):
    return any(re.search(p, path) for p in BENIGN_PATTERNS)


def severity(change_type, path):
    critical = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/.ssh",
                "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "cron", "systemd"]
    if change_type == "Added" and "/home/" in path and path.endswith(".php"):
        return "tinggi"
    if any(c in path for c in critical):
        return "tinggi"
    if change_type in ("Changed", "Added") and "/home/" in path:
        return "sedang"
    if change_type == "Removed":
        return "sedang"
    return "rendah"


def parse_aide_output(raw):
    items = []
    section = None
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        if ln.endswith(":") and ln.rstrip(":") in (
            "Changed files", "Added files", "Removed files", "Changed attributes"
        ):
            section = ln.rstrip(":").replace(" files", "").replace(" attributes", "")
            continue
        m = re.match(r"^(file|directory|fifO|fifo|socket|block device|character device):\s*(.+)$", ln)
        if m and section:
            path = m.group(2).strip()
            items.append({
                "change": section,
                "path": path,
                "severity": severity(section, path),
                "benign": is_benign(path),
            })
    return items


def do_check():
    if not os.path.isfile("/var/lib/aide/aide.db"):
        print("error: baseline AIDE belum ada — jalankan aidescan.py init dulu")
        return
    cmd = ["aide", "--config=/etc/aide/aide.conf", "--check"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        raw = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        raw = "error: AIDE timeout (>60 menit)"
    except Exception as e:
        raw = "error: %s" % e

    if os.path.isfile(LOG):
        try:
            with open(LOG, "r", errors="replace") as f:
                raw += "\n" + f.read()[-80000:]
        except OSError:
            pass

    clean = "found no differences" in raw.lower()
    items = [] if clean else parse_aide_output(raw)
    real = [i for i in items if not i["benign"]]
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "clean": clean,
        "total_changes": len(items),
        "real_changes": len(real),
        "benign_changes": len(items) - len(real),
        "high": len([i for i in real if i["severity"] == "tinggi"]),
        "items": items[:500],
    }
    os.makedirs(DATA, exist_ok=True)
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, OUT)
    if clean:
        print("AIDE selesai: tidak ada perubahan file")
    else:
        print("AIDE selesai: %d perubahan (%d perlu ditinjau, %d diabaikan)"
              % (data["total_changes"], data["real_changes"], data["benign_changes"]))


def do_init():
    cmd = ["aideinit", "-y", "-f"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=7200)
        out = (r.stdout or "") + (r.stderr or "")
        print(out[-2000:])
        if os.path.isfile("/var/lib/aide/aide.db"):
            print("Baseline AIDE siap.")
        else:
            print("Perhatian: cek /var/lib/aide/ — init mungkin masih berjalan")
    except subprocess.TimeoutExpired:
        print("error: aideinit timeout (>2 jam)")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    if action == "init":
        do_init()
    else:
        do_check()
