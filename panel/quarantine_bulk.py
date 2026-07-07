#!/usr/bin/env python3
"""Bulk quarantine — jalankan sebagai background job dari panel.

Usage:
  quarantine_bulk.py SOURCE [DOMAIN] [MIN_SCORE]
  quarantine_bulk.py --file /path/to/paths.json

SOURCE: imunify | backdoor | malware | all | selected (via --file)
DOMAIN: ALL atau path public_html (default ALL)
MIN_SCORE: threshold backdoor (default 12)
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import time

BASE = "/usr/local/maldetect-panel"
DATA = os.path.join(BASE, "data")
QSTORE = os.path.join(BASE, "quar_store")
WL_FILE = os.path.join(DATA, "whitelist.json")
QM_FILE = os.path.join(DATA, "quarantine.json")
MALDET_SESS = "/usr/local/maldetect/sess"
CONF = os.path.join(BASE, "panel.conf")


def _load_allowed_prefix():
    try:
        with open(CONF) as f:
            for line in f:
                line = line.strip()
                if line.startswith("ALLOWED_PREFIX="):
                    vals = line.split("=", 1)[1].strip()
                    out = tuple(p.strip() for p in vals.split(",") if p.strip())
                    if out:
                        return out
    except FileNotFoundError:
        pass
    return ("/home/", "/var/www/", "/srv/", "/tmp/", "/var/tmp/")


ALLOWED_PREFIX = _load_allowed_prefix()


def read_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def wl_paths_enabled():
    return {e["path"] for e in read_json(WL_FILE, []) if e.get("enabled")}


def qm_paths():
    return {e.get("orig", "") for e in read_json(QM_FILE, [])}


def domain_match(path, domain):
    if not domain or domain == "ALL":
        return True
    if domain.startswith("/"):
        return path.startswith(domain.rstrip("/") + "/") or path == domain
    # domain berupa nama (bukan path): cocokkan di layout apapun
    return ("/%s/" % domain) in path


def quarantine(path, reason=""):
    if not any(path.startswith(a) for a in ALLOWED_PREFIX):
        return {"error": "path di luar area yang diizinkan"}
    if not os.path.isfile(path):
        return {"error": "file tidak ada"}
    if path in wl_paths_enabled():
        return {"error": "whitelist"}
    try:
        st = os.lstat(path)
        qid = time.strftime("%y%m%d-%H%M%S") + "-" + os.path.basename(path)
        stored = os.path.join(QSTORE, qid)
        shutil.move(path, stored)
        os.chmod(stored, 0)
        if os.path.lexists(path):
            try:
                os.remove(path)
            except Exception:
                pass
        entry = {
            "id": qid, "orig": path, "stored": stored, "size": st.st_size,
            "mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid,
            "at": time.strftime("%Y-%m-%d %H:%M"), "reason": reason,
        }
        qm = read_json(QM_FILE, [])
        qm.append(entry)
        write_json(QM_FILE, qm)
        subprocess.run(
            ["python3", os.path.join(BASE, "imavscan.py"), "remove-listed", path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return {"ok": True, "id": qid}
    except Exception as e:
        return {"error": str(e)}


def collect_malware_paths():
    hits = []
    files = sorted(glob.glob(os.path.join(MALDET_SESS, "session.hits.*")),
                   key=os.path.getmtime, reverse=True)
    if not files:
        return hits
    seen = set()
    for line in open(files[0], "r", errors="replace"):
        line = line.strip()
        if " : " in line:
            _, _, path = line.partition(" : ")
            path = path.strip()
            if path and path not in seen:
                seen.add(path)
                hits.append(path)
    return hits


def collect_paths(source, domain="ALL", min_score=12):
    wl = wl_paths_enabled()
    done = qm_paths()
    out = []

    def add(path):
        if not path or path in wl or path in done:
            return
        if not domain_match(path, domain):
            return
        if path not in out:
            out.append(path)

    if source in ("imunify", "all"):
        im = read_json(os.path.join(DATA, "imunify_latest.json"), {})
        for it in im.get("items", []):
            add(it.get("path", ""))

    if source in ("backdoor", "all"):
        bd = read_json(os.path.join(DATA, "backdoor_latest.json"), {})
        for it in bd.get("items", []):
            if it.get("score", 0) >= min_score:
                add(it.get("path", ""))

    if source in ("malware", "all"):
        for path in collect_malware_paths():
            add(path)

    return out


def main():
    if len(sys.argv) > 2 and sys.argv[1] == "--file":
        paths = read_json(sys.argv[2], [])
        if not isinstance(paths, list):
            print("File paths harus berisi array JSON")
            return 1
        source = "selected"
        domain = "CHECKBOX"
    else:
        source = (sys.argv[1] if len(sys.argv) > 1 else "all").lower()
        domain = sys.argv[2] if len(sys.argv) > 2 else "ALL"
        min_score = int(sys.argv[3]) if len(sys.argv) > 3 and str(sys.argv[3]).isdigit() else 12
        if source not in ("imunify", "backdoor", "malware", "all"):
            print("SOURCE tidak dikenal:", source)
            return 1
        paths = collect_paths(source, domain, min_score)
    print("=== Bulk Karantina [%s] domain=%s ===" % (source, domain))
    print("Target: %d file" % len(paths))
    if not paths:
        print("Tidak ada file untuk dikarantina (kosong / sudah Q / whitelist).")
        return 0

    ok, skipped, failed = 0, 0, 0
    for i, path in enumerate(paths, 1):
        print("[%d/%d] %s" % (i, len(paths), path))
        res = quarantine(path, reason="bulk:%s" % source)
        if res.get("ok"):
            ok += 1
            print("  -> OK")
        elif res.get("error") == "whitelist":
            skipped += 1
            print("  -> skip (whitelist)")
        else:
            failed += 1
            print("  -> GAGAL:", res.get("error"))

    if source in ("imunify", "all", "selected"):
        print("Sync Imunify malicious list...")
        subprocess.run(["python3", os.path.join(BASE, "imavscan.py"), "sync"])

    print("=== RINGKASAN ===")
    print("Berhasil : %d" % ok)
    print("Gagal    : %d" % failed)
    print("Skip WL  : %d" % skipped)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
