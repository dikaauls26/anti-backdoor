#!/usr/bin/env python3
"""ImunifyAV integration — scan, sync malicious list, bridge ke panel karantina.

ImunifyAV(+) v6.2+ tidak punya tombol Quarantine/Delete di UI/CLI.
Panel ini mengisi celah itu: Imunify scan → temuan masuk panel → karantina manual.

Usage:
  imavscan.py sync              -> tarik malicious list ke data/imunify_latest.json
  imavscan.py scan PATH         -> on-demand scan satu path
  imavscan.py scan-all          -> scan semua public_html
  imavscan.py remove-listed P   -> hapus dari Imunify malicious list (setelah karantina)
  imavscan.py status            -> cek imunify-antivirus terpasang
"""
import json
import os
import re
import subprocess
import sys
import time

BASE = "/usr/local/maldetect-panel"
DATA = os.path.join(BASE, "data")
CONF = os.path.join(BASE, "panel.conf")
OUT = os.path.join(DATA, "imunify_latest.json")
IMAV = "/usr/bin/imunify-antivirus"
ALT_IMAV = "/usr/sbin/imunify-antivirus"


def web_root_globs():
    roots = "/home/*/public_html"
    try:
        with open(CONF) as f:
            for line in f:
                line = line.strip()
                if line.startswith("WEB_ROOTS="):
                    roots = line.split("=", 1)[1].strip()
    except FileNotFoundError:
        pass
    return [p.strip() for p in roots.split(",") if p.strip()]


def imav_bin():
    for p in (IMAV, ALT_IMAV):
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    found = subprocess.run(
        "command -v imunify-antivirus 2>/dev/null || command -v imunify360-agent 2>/dev/null",
        shell=True, capture_output=True, text=True,
    ).stdout.strip()
    return found or None


def run(cmd, timeout=3600):
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return -1, "timeout"
    except Exception as e:
        return -1, str(e)


def parse_json_output(raw):
    raw = raw.strip()
    if not raw:
        return None
    # Imunify kadang mencetak banner sebelum JSON
    start = raw.find("{")
    end = raw.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(raw[start:end + 1])
        except json.JSONDecodeError:
            pass
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def normalize_items(data):
    items = []
    if not data:
        return items
    raw_items = data.get("items") or data.get("malicious") or data.get("data") or []
    if isinstance(raw_items, dict):
        raw_items = list(raw_items.values())
    for it in raw_items:
        if isinstance(it, str):
            items.append({"path": it, "signature": "ImunifyAV", "id": None, "user": ""})
            continue
        path = (
            it.get("file") or it.get("path") or it.get("filename")
            or it.get("original_filename") or ""
        )
        if not path:
            continue
        items.append({
            "id": it.get("id"),
            "path": path,
            "signature": it.get("signature") or it.get("virus") or it.get("type") or "ImunifyAV",
            "user": it.get("user") or it.get("username") or "",
            "scan_id": it.get("scan_id"),
            "created": it.get("created") or it.get("date") or "",
        })
    return items


def parse_text_list(raw):
    items = []
    for ln in raw.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        m = re.match(r"^\s*(\d+)\s+(.+)$", ln)
        if m:
            items.append({
                "id": int(m.group(1)),
                "path": m.group(2).strip(),
                "signature": "ImunifyAV",
                "user": "",
            })
            continue
        if ln.startswith("/"):
            items.append({"id": None, "path": ln, "signature": "ImunifyAV", "user": ""})
    return items


def do_sync():
    bin_ = imav_bin()
    if not bin_:
        out = {"ok": False, "error": "imunify-antivirus tidak terpasang", "items": []}
        os.makedirs(DATA, exist_ok=True)
        with open(OUT, "w") as f:
            json.dump(out, f)
        print(json.dumps(out))
        return 1

    code, raw = run("%s malware malicious list --limit 1000 --json 2>/dev/null" % bin_, timeout=120)
    data = parse_json_output(raw)
    items = normalize_items(data) if data else []
    if not items:
        code2, raw2 = run("%s malware malicious list --limit 1000 2>/dev/null" % bin_, timeout=120)
        items = parse_text_list(raw2)
        if code != 0 and code2 != 0 and not items:
            out = {"ok": False, "error": (raw2 or raw)[:500], "items": []}
            with open(OUT, "w") as f:
                json.dump(out, f)
            print(json.dumps(out))
            return 1

    ver_out = run("%s version 2>/dev/null | head -1" % bin_)[1].strip()
    out = {
        "ok": True,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version": ver_out,
        "count": len(items),
        "items": items,
    }
    os.makedirs(DATA, exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(out, f)
    print(json.dumps({"ok": True, "count": len(items)}))
    return 0


def do_scan(path):
    bin_ = imav_bin()
    if not bin_:
        print(json.dumps({"error": "imunify-antivirus tidak terpasang"}))
        return 1
    esc = path.replace("'", "'\\''")
    code, raw = run("%s malware on-demand start --path '%s' 2>&1" % (bin_, esc), timeout=60)
    print(raw or ("exit %s" % code))
    # Tunggu sebentar lalu sync daftar malicious
    time.sleep(5)
    do_sync()
    return code


def do_scan_all():
    bin_ = imav_bin()
    if not bin_:
        print("imunify-antivirus tidak terpasang")
        return 1
    # Coba scan per-user (lebih mirip GUI "Scan all")
    code, raw = run("%s malware user scan 2>&1" % bin_, timeout=7200)
    print(raw)
    if code != 0:
        # fallback: queue tiap web root sesuai WEB_ROOTS
        import glob
        seen = set()
        for pat in web_root_globs():
            for p in sorted(glob.glob(pat)):
                if p in seen:
                    continue
                seen.add(p)
                print("==> scan %s" % p)
                do_scan(p)
    do_sync()
    return 0


def do_remove_listed(path):
    bin_ = imav_bin()
    if not bin_ or not path:
        return {"ok": False, "skipped": True}
    esc = path.replace("'", "'\\''")
    run("%s malware malicious remove-from-list --file '%s' 2>/dev/null" % (bin_, esc), timeout=30)
    return {"ok": True}


def do_status():
    bin_ = imav_bin()
    if not bin_:
        print(json.dumps({"installed": False}))
        return 1
    ver = run("%s version 2>/dev/null | head -1" % bin_)[1].strip()
    print(json.dumps({"installed": True, "binary": bin_, "version": ver}))
    return 0


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    cmd = sys.argv[1]
    if cmd == "sync":
        return do_sync()
    if cmd == "scan":
        if len(sys.argv) < 3:
            print("usage: imavscan.py scan /path")
            return 1
        return do_scan(sys.argv[2])
    if cmd == "scan-all":
        return do_scan_all()
    if cmd == "remove-listed":
        if len(sys.argv) < 3:
            return 1
        print(json.dumps(do_remove_listed(sys.argv[2])))
        return 0
    if cmd == "status":
        return do_status()
    print("perintah tidak dikenal:", cmd)
    return 1


if __name__ == "__main__":
    sys.exit(main())
