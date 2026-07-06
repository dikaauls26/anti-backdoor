#!/usr/bin/env python3
"""Lynis security audit for security panel.

Usage:
  lynisscan.py audit  -> jalankan audit, tulis lynis_latest.json
"""
import os
import re
import sys
import json
import time
import subprocess

BASE = "/usr/local/maldetect-panel"
DATA = os.path.join(BASE, "data")
OUT = os.path.join(DATA, "lynis_latest.json")
REPORT = "/var/log/lynis-report.dat"


def parse_report_dat():
    items = []
    score = None
    if not os.path.isfile(REPORT):
        return items, score
    with open(REPORT, "r", errors="replace") as f:
        for ln in f:
            ln = ln.strip()
            if ln.startswith("hardening_index="):
                try:
                    score = int(ln.split("=", 1)[1])
                except Exception:
                    pass
                continue
            kind = None
            if ln.startswith("warning[]="):
                kind = "warning"
                raw = ln.split("=", 1)[1]
            elif ln.startswith("suggestion[]="):
                kind = "suggestion"
                raw = ln.split("=", 1)[1]
            else:
                continue
            parts = raw.split("|")
            code = parts[0] if parts else ""
            text = parts[1] if len(parts) > 1 else raw
            if code == "LYNIS" and "old" in text.lower():
                continue
            sev = "rendah"
            if kind == "warning":
                sev = "tinggi" if any(k in text.lower() for k in (
                    "malware", "rootkit", "compromised", "no password", "permitroot"
                )) else "sedang"
            items.append({"type": kind, "code": code, "text": text, "severity": sev})
    return items, score


def parse_stdout(raw):
    items = []
    score = None
    for ln in raw.splitlines():
        m = re.search(r"Hardening index\s*:\s*\[?(\d+)\]?", ln)
        if m:
            score = int(m.group(1))
        m = re.match(r"\[\s*(warning|suggestion)\s*\]\s*(.*)", ln, re.I)
        if m:
            kind, text = m.group(1).lower(), m.group(2).strip()
            sev = "tinggi" if kind == "warning" and any(k in text.lower() for k in (
                "malware", "rootkit", "compromised", "critical"
            )) else ("sedang" if kind == "warning" else "rendah")
            items.append({"type": kind, "code": "", "text": text, "severity": sev})
    return items, score


def do_audit():
    cmd = ["lynis", "audit", "system", "--quick", "--no-colors"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        raw = (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        raw = "error: Lynis timeout (>15 menit)"
    except Exception as e:
        raw = "error: %s" % e

    items, score = parse_report_dat()
    if score is None or not items:
        items2, score2 = parse_stdout(raw)
        if not items:
            items = items2
        if score is None:
            score = score2

    warnings = [i for i in items if i["type"] == "warning"]
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "hardening_score": score,
        "total": len(items),
        "warnings": len(warnings),
        "suggestions": len([i for i in items if i["type"] == "suggestion"]),
        "high": len([i for i in items if i["severity"] == "tinggi"]),
        "items": items[:300],
    }
    os.makedirs(DATA, exist_ok=True)
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, OUT)
    print("Lynis selesai: skor %s, %d warning, %d saran"
          % (score if score is not None else "?", data["warnings"], data["suggestions"]))


if __name__ == "__main__":
    do_audit()
