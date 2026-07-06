#!/usr/bin/env python3
"""Inspect file findings: read source, map web URL, probe HTTP response."""
import os
import re
import json
import time
import pwd
import subprocess

ALLOWED_PREFIX = ("/home/", "/tmp/", "/var/tmp/")
MAX_BYTES = 120000
MAX_LINES = 450

DANGER_RE = [
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(", re.I),
    re.compile(r"base64_decode\s*\(", re.I),
    re.compile(r"\$_(POST|GET|REQUEST|COOKIE)\b", re.I),
    re.compile(r"FilesMan|c99shell|r57shell|b374k|WSOshell|IndoXploit", re.I),
    re.compile(r"gzinflate|gzuncompress|str_rot13", re.I),
    re.compile(r"php://input", re.I),
]


def path_to_url(path):
    if path.startswith("/home/") and "/public_html/" in path:
        domain, rest = path.split("/public_html/", 1)
        domain = domain.replace("/home/", "")
        return "https://%s/%s" % (domain, rest)
    return None


def validate_path(path):
    if not path or not any(path.startswith(a) for a in ALLOWED_PREFIX):
        return "path di luar area yang diizinkan"
    if not os.path.isfile(path):
        return "file tidak ada"
    return None


def run_curl(url):
    pid = os.getpid()
    body_f = "/tmp/scanpanel_probe_%s.body" % pid
    hdr_f = "/tmp/scanpanel_probe_%s.hdr" % pid
    for f in (body_f, hdr_f):
        try:
            os.remove(f)
        except OSError:
            pass
    cmd = (
        "curl -sk -D '%s' -o '%s' --max-time 12 "
        "-w '%%{http_code}|%%{content_type}|%%{size_download}' '%s' 2>/dev/null"
    ) % (hdr_f, body_f, url)
    try:
        meta = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=18)
        raw = (meta.stdout or "").strip()
    except Exception as e:
        return {"error": str(e)}
    parts = raw.split("|") if "|" in raw else ["0", "", "0"]
    while len(parts) < 3:
        parts.append("0")
    code, ctype, size = parts[0], parts[1], parts[2]
    body, headers = "", ""
    try:
        with open(body_f, "r", errors="replace") as f:
            body = f.read(8000)
    except OSError:
        pass
    try:
        with open(hdr_f, "r", errors="replace") as f:
            headers = f.read(1500)
    except OSError:
        pass
    return {"code": code, "ctype": ctype, "size": size, "body": body, "headers": headers}


def analyze_probe(body, code, ctype, path):
    code = str(code)
    bl = body.lower()
    is_php = ".php" in path.lower()

    if code in ("0", "000", ""):
        return "tidak_terjangkau", "Tidak bisa dijangkau dari server (timeout / gagal koneksi)."
    if code == "404":
        return "not_found", "HTTP 404 — file tidak bisa diakses via web (bagus jika memang disembunyikan)."
    if code == "403":
        return "forbidden", "HTTP 403 — akses diblokir web server."
    if code == "500":
        return "server_error", "HTTP 500 — error PHP/eksekusi. Bisa indikasi backdoor rusak atau aktif."

    head = body[:3000]
    if is_php and ("<?php" in head or "<?=" in head):
        if re.search(r"\b(eval|system|shell_exec|passthru|base64_decode)\s*\(", head, re.I):
            return "source_exposed", (
                "Source PHP terbaca di response (tidak dieksekusi). "
                "File berbahaya tetap ada di server — segera karantina."
            )

    if re.search(r"(uid=\d+|gid=\d+|www-data|root:|/bin/(ba)?sh|command not found)", body, re.I):
        return "backdoor_aktif", "Response mengandung output shell/OS — KEMUNGKINAN BACKDOOR AKTIF!"

    if re.search(r"(c99shell|r57shell|FilesMan|IndoXploit|uname\s+-a|Safe\s*Mode)", body, re.I):
        return "webshell_response", "Response mirip webshell — sangat berbahaya!"

    if re.search(r"(viagra|casino|slot\s*gacor|payday|porn)", bl):
        return "spam_inject", "Response mengandung spam SEO / redirect malware."

    if "text/html" in (ctype or "").lower() and len(body) > 80:
        return "html_response", "HTTP %s mengembalikan HTML — periksa apakah redirect/spam." % code

    if code == "200" and len(body.strip()) < 30:
        return "empty_ok", "HTTP 200 tapi response hampir kosong — mungkin backdoor menunggu parameter."

    return "unknown", "HTTP %s — lihat preview response untuk penilaian manual." % code


VERDICT_UI = {
    "backdoor_aktif": {"label": "BACKDOOR AKTIF", "level": "danger"},
    "webshell_response": {"label": "WEBSHELL", "level": "danger"},
    "source_exposed": {"label": "Source PHP Terbaca", "level": "warning"},
    "spam_inject": {"label": "Spam / Inject", "level": "warning"},
    "server_error": {"label": "Error Server", "level": "warning"},
    "forbidden": {"label": "Diblokir (403)", "level": "success"},
    "not_found": {"label": "Tidak Ditemukan (404)", "level": "success"},
    "empty_ok": {"label": "Response Kosong", "level": "info"},
    "html_response": {"label": "HTML Response", "level": "info"},
    "tidak_terjangkau": {"label": "Tidak Terjangkau", "level": "secondary"},
    "unknown": {"label": "Perlu Dicek", "level": "secondary"},
}


def highlight_lines(text):
    hl = set()
    for i, line in enumerate(text.splitlines(), 1):
        for rx in DANGER_RE:
            if rx.search(line):
                hl.add(i)
                break
    return sorted(hl)


def file_detail(path):
    err = validate_path(path)
    if err:
        return {"error": err}
    st = os.stat(path)
    try:
        owner = pwd.getpwuid(st.st_uid).pw_name
    except Exception:
        owner = str(st.st_uid)
    with open(path, "r", errors="replace") as f:
        raw = f.read(MAX_BYTES)
    truncated = st.st_size > MAX_BYTES
    all_lines = raw.splitlines()
    lines = all_lines[:MAX_LINES]
    hl = highlight_lines(raw)
    url = path_to_url(path)
    return {
        "path": path,
        "url": url,
        "size": st.st_size,
        "size_human": "%.1f KB" % (st.st_size / 1024) if st.st_size > 1024 else "%d B" % st.st_size,
        "mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime)),
        "owner": owner,
        "truncated": truncated or len(all_lines) > MAX_LINES,
        "lines": [{"n": i + 1, "text": ln, "hl": (i + 1) in hl} for i, ln in enumerate(lines)],
        "line_count": len(all_lines),
        "highlight_count": len(hl),
    }


def file_probe(path):
    err = validate_path(path)
    if err:
        return {"error": err}
    url = path_to_url(path)
    if not url:
        return {"error": "File tidak punya URL web (bukan di public_html). Hanya bisa lihat source code."}
    res = run_curl(url)
    if res.get("error"):
        return {"error": res["error"]}
    verdict, note = analyze_probe(res["body"], res["code"], res["ctype"], path)
    ui = VERDICT_UI.get(verdict, VERDICT_UI["unknown"])
    dangerous = verdict in ("backdoor_aktif", "webshell_response", "source_exposed", "spam_inject")
    return {
        "url": url,
        "http_code": int(res["code"]) if str(res["code"]).isdigit() else 0,
        "content_type": res["ctype"],
        "size": int(float(res["size"])) if res["size"] else 0,
        "body_preview": res["body"][:4000],
        "headers_preview": res["headers"][:1200],
        "verdict": verdict,
        "verdict_label": ui["label"],
        "verdict_level": ui["level"],
        "verdict_note": note,
        "is_dangerous": dangerous,
    }


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print(json.dumps({"error": "usage: fileinspect.py detail|probe <path>"}))
        raise SystemExit(1)
    action, path = sys.argv[1], sys.argv[2]
    if action == "detail":
        print(json.dumps(file_detail(path)))
    elif action == "probe":
        print(json.dumps(file_probe(path)))
    else:
        print(json.dumps({"error": "aksi tidak dikenal"}))
