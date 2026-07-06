#!/usr/bin/env python3
"""Run rkhunter, parse warnings into JSON for the security panel.

Usage:
  rkscan.py check    -> jalankan scan, tulis data/rkhunter_latest.json
  rkscan.py update   -> perbarui database + baseline properties
"""
import os
import re
import sys
import json
import time
import subprocess

BASE = "/usr/local/maldetect-panel"
DATA = os.path.join(BASE, "data")
OUT = os.path.join(DATA, "rkhunter_latest.json")
LOG = "/var/log/rkhunter.log"

# Warning yang aman diabaikan di server CyberPanel + OpenLiteSpeed.
BENIGN_PATTERNS = [
    r"/dev/shm/ols", r"/dev/shm/lsmcd", r"/dev/shm/\.quicshm",
    r"PermitRootLogin", r"ALLOW_SSH_ROOT_USER",
    r"/usr/\.tempdisk",
    r"os\.release\.txt", r"needs journal recovery",
]


def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def is_benign(text):
    return any(re.search(p, text) for p in BENIGN_PATTERNS)


def severity(text):
    t = text.lower()
    hi = ["rootkit", "trojan", "backdoor", "infected", "malware",
          "hidden process", "promiscuous", "suspicious file"]
    if any(k in t for k in hi):
        return "tinggi"
    if "hidden file" in t or "script replacement" in t or "changed" in t:
        return "sedang"
    return "rendah"


def parse_warnings(raw):
    lines = strip_ansi(raw).splitlines()
    items = []
    cur = None
    for ln in lines:
        m = re.match(r"\s*Warning:\s*(.*)", ln)
        if m:
            if cur:
                items.append(cur)
            head = m.group(1).strip()
            cur = {"title": head, "detail": []}
        elif cur is not None and ln.strip() and (ln.startswith(" ") or ln.startswith("\t")):
            cur["detail"].append(ln.strip())
        else:
            if cur:
                items.append(cur)
                cur = None
    if cur:
        items.append(cur)

    out = []
    for it in items:
        full = it["title"] + " " + " ".join(it["detail"])
        out.append({
            "title": it["title"],
            "detail": " | ".join(it["detail"])[:500],
            "severity": severity(full),
            "benign": is_benign(full),
        })
    return out


def do_check():
    cmd = ["rkhunter", "--check", "--sk", "--nocolors", "--rwo", "--no-mail-on-warning"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        raw = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        raw = "error: rkhunter timeout (>20 menit)"
    except Exception as e:
        raw = "error: %s" % e

    warnings = parse_warnings(raw)
    real = [w for w in warnings if not w["benign"]]
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_warnings": len(warnings),
        "real_warnings": len(real),
        "benign_warnings": len(warnings) - len(real),
        "high": len([w for w in real if w["severity"] == "tinggi"]),
        "items": warnings,
    }
    os.makedirs(DATA, exist_ok=True)
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, OUT)
    print("rkhunter selesai: %d warning (%d perlu ditinjau, %d aman diabaikan)"
          % (data["total_warnings"], data["real_warnings"], data["benign_warnings"]))


def do_update():
    subprocess.run(["rkhunter", "--update"], timeout=300)
    subprocess.run(["rkhunter", "--propupd"], timeout=300)
    print("Update database & baseline rkhunter selesai.")


if __name__ == "__main__":
    action = sys.argv[1] if len(sys.argv) > 1 else "check"
    if action == "update":
        do_update()
    else:
        do_check()
