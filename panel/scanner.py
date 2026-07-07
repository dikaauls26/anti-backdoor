#!/usr/bin/env python3
"""Heuristic backdoor/webshell scanner + new-file detector (per-domain aware).
Usage:
  scanner.py backdoor [threshold] [target]
  scanner.py newfiles [days] [target]
target = a specific /home/<domain>/public_html path, or "ALL" (default).
Writes JSON results into /usr/local/maldetect-panel/data/ and prints a
human-readable summary (captured as the job log).
"""
import sys
import os
import re
import json
import glob
import time
import pwd
import hashlib
import urllib.request
import urllib.error

BASE = "/usr/local/maldetect-panel"
DATA = os.path.join(BASE, "data")
CONF = os.path.join(BASE, "panel.conf")


def load_conf():
    cfg = {"WEB_ROOTS": "/home/*/public_html"}
    try:
        with open(CONF) as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return cfg


PHP_EXT = (".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".pht",
           ".inc", ".suspected", ".module")
RISKY_NONPHP = (".ico", ".gif", ".jpg", ".jpeg", ".png", ".txt", ".log",
                ".json", ".css", ".js", ".htaccess", "")
SKIP_DIRS = {".git", "node_modules", ".well-known"}
MAX_READ = 3 * 1024 * 1024

INDICATORS = [
    (re.compile(rb"\beval\s*\("), 5, "eval() - jalankan kode PHP dinamis"),
    (re.compile(rb"\bassert\s*\("), 5, "assert() - bisa eksekusi kode"),
    (re.compile(rb"create_function\s*\("), 4, "create_function() - eval terselubung"),
    (re.compile(rb"\bsystem\s*\("), 5, "system() - jalankan perintah OS"),
    (re.compile(rb"\bexec\s*\("), 4, "exec() - jalankan perintah OS"),
    (re.compile(rb"shell_exec\s*\("), 5, "shell_exec() - jalankan perintah shell"),
    (re.compile(rb"passthru\s*\("), 5, "passthru() - jalankan perintah OS"),
    (re.compile(rb"\bpopen\s*\("), 4, "popen() - buka proses"),
    (re.compile(rb"proc_open\s*\("), 5, "proc_open() - buka proses"),
    (re.compile(rb"pcntl_exec\s*\("), 5, "pcntl_exec() - eksekusi proses"),
    (re.compile(rb"base64_decode\s*\("), 2, "base64_decode() - dekode payload"),
    (re.compile(rb"gzinflate\s*\("), 3, "gzinflate() - dekompres payload"),
    (re.compile(rb"gzuncompress\s*\("), 3, "gzuncompress() - dekompres payload"),
    (re.compile(rb"str_rot13\s*\("), 3, "str_rot13() - samarkan payload"),
    (re.compile(rb"preg_replace\s*\(\s*[\"'][^\"']*/e"), 6, "preg_replace /e - eksekusi kode"),
    (re.compile(rb"move_uploaded_file\s*\("), 1, "move_uploaded_file() - terima upload"),
    (re.compile(rb"edoced_46esab"), 6, "base64_decode ditulis terbalik (obfuscation)"),
    (re.compile(rb"FilesMan|c99shell|r57shell|b374k|WSOshell|IndoXploit|MiniShell|Sh3ll|marijuana|priv8", re.I), 8, "penanda webshell terkenal"),
    (re.compile(rb"\$_(POST|GET|REQUEST|COOKIE)\b"), 1, "pakai input pengguna ($_POST/$_GET/...)"),
    (re.compile(rb"php://input"), 2, "php://input - baca body request"),
    (re.compile(rb"\$\$[a-zA-Z_]"), 2, "variable-variable (obfuscation)"),
    (re.compile(rb"chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\("), 2, "rangkaian chr() (obfuscation)"),
]
EXEC_TOKENS = re.compile(rb"\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(")
INPUT_TOKENS = re.compile(rb"\$_(POST|GET|REQUEST|COOKIE)\b")
HEX_ESC = re.compile(rb"\\x[0-9a-fA-F]{2}")
LONG_B64 = re.compile(rb"[A-Za-z0-9+/]{300,}={0,2}")


def owner(path):
    try:
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except Exception:
        return "?"


def expand_all_roots(cfg):
    roots = []
    for pat in cfg["WEB_ROOTS"].split(","):
        pat = pat.strip()
        if pat:
            roots.extend(glob.glob(pat))
    return roots


def resolve_targets(cfg, target):
    if target and target.upper() != "ALL":
        return [target], False
    return expand_all_roots(cfg), True


def snippet_for(data):
    m = EXEC_TOKENS.search(data) or LONG_B64.search(data) or INDICATORS[0][0].search(data)
    if not m:
        return ""
    start = data.rfind(b"\n", 0, m.start()) + 1
    end = data.find(b"\n", m.start())
    if end < 0:
        end = len(data)
    return data[start:end].decode("utf-8", "replace").strip()[:180]


def scan_file(path):
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    ext = os.path.splitext(path)[1].lower()
    is_php = ext in PHP_EXT
    if not is_php:
        if ext not in RISKY_NONPHP or size > MAX_READ:
            return None
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_READ)
    except OSError:
        return None
    if not is_php and b"<?php" not in data and b"<?=" not in data:
        return None
    score = 0
    found = []
    for rx, w, label in INDICATORS:
        n = len(rx.findall(data))
        if n:
            found.append({"label": label, "count": n, "weight": w})
            score += w
    hx = len(HEX_ESC.findall(data))
    if hx > 30:
        found.append({"label": "banyak escape heksadesimal (\\xNN)", "count": hx, "weight": 3})
        score += 3
    if LONG_B64.search(data):
        found.append({"label": "blok base64 sangat panjang (payload tersembunyi)", "count": 1, "weight": 3})
        score += 3
    if EXEC_TOKENS.search(data) and INPUT_TOKENS.search(data):
        found.append({"label": "KOMBO: eksekusi kode + input pengguna langsung", "count": 1, "weight": 4})
        score += 4
    if not found:
        return None
    st = os.stat(path)
    return {
        "path": path,
        "score": score,
        "size": size,
        "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
        "mtime_ts": int(st.st_mtime),
        "owner": owner(path),
        "ext": ext or "(none)",
        "is_php_named": is_php,
        "indicators": sorted(found, key=lambda x: -x["weight"]),
        "snippet": snippet_for(data),
    }


def do_backdoor(threshold, target):
    cfg = load_conf()
    roots, is_all = resolve_targets(cfg, target)
    scandirs = list(roots)
    if is_all:
        scandirs += ["/tmp", "/var/tmp"]
    scanned = 0
    items = []
    print("Scan anti-backdoor dimulai: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    print("Target: %s" % ("SEMUA DOMAIN + /tmp" if is_all else target))
    print("Threshold skor: %d" % threshold)
    print("-" * 60)
    for root in scandirs:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                p = os.path.join(dirpath, name)
                if os.path.islink(p):
                    continue
                scanned += 1
                if scanned % 2000 == 0:
                    print("  ...diperiksa %d file" % scanned)
                r = scan_file(p)
                if r and r["score"] >= threshold:
                    items.append(r)
    items.sort(key=lambda x: -x["score"])
    items = items[:400]
    out = {
        "type": "backdoor",
        "target": ("ALL" if is_all else target),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "generated_ts": int(time.time()),
        "threshold": threshold,
        "scanned_files": scanned,
        "flagged": len(items),
        "items": items,
    }
    os.makedirs(DATA, exist_ok=True)
    with open(os.path.join(DATA, "backdoor_latest.json"), "w") as f:
        json.dump(out, f)
    print("-" * 60)
    print("Selesai. File diperiksa: %d, dicurigai: %d" % (scanned, len(items)))
    for it in items[:40]:
        labs = ", ".join(i["label"].split(" - ")[0].split(" (")[0] for i in it["indicators"][:5])
        print("[skor %3d] %s" % (it["score"], it["path"]))
        print("           owner=%s ubah=%s ukuran=%dB | %s" % (it["owner"], it["mtime"], it["size"], labs))
    if len(items) > 40:
        print("... dan %d file lain (lihat tab Temuan)." % (len(items) - 40))


def do_newfiles(days, target):
    cfg = load_conf()
    roots, is_all = resolve_targets(cfg, target)
    cutoff = time.time() - days * 86400
    items = []
    scanned = 0
    print("Deteksi file baru/berubah <= %d hari: %s" % (days, time.strftime("%Y-%m-%d %H:%M:%S")))
    print("Target: %s" % ("SEMUA DOMAIN" if is_all else target))
    print("-" * 60)
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                p = os.path.join(dirpath, name)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                scanned += 1
                if st.st_mtime >= cutoff:
                    ext = os.path.splitext(name)[1].lower()
                    items.append({
                        "path": p,
                        "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
                        "mtime_ts": int(st.st_mtime),
                        "size": st.st_size,
                        "owner": owner(p),
                        "ext": ext or "(none)",
                        "is_php": ext in PHP_EXT,
                    })
    items.sort(key=lambda x: -x["mtime_ts"])
    items = items[:600]
    out = {
        "type": "newfiles",
        "target": ("ALL" if is_all else target),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "generated_ts": int(time.time()),
        "days": days,
        "scanned_files": scanned,
        "found": len(items),
        "items": items,
    }
    os.makedirs(DATA, exist_ok=True)
    with open(os.path.join(DATA, "newfiles_latest.json"), "w") as f:
        json.dump(out, f)
    print("-" * 60)
    print("Selesai. Total file: %d, baru/berubah: %d" % (scanned, len(items)))
    php = [i for i in items if i["is_php"]]
    print(">> File PHP baru/berubah (paling penting): %d" % len(php))
    for it in php[:40]:
        print("  %s  %s  %dB  (%s)" % (it["mtime"], it["path"], it["size"], it["owner"]))


WP_CORE_PREFIXES = ("wp-includes/", "wp-admin/")
WP_ROOT_FILES = {
    "index.php", "wp-activate.php", "wp-blog-header.php", "wp-comments-post.php",
    "wp-config-sample.php", "wp-cron.php", "wp-links-opml.php", "wp-load.php",
    "wp-login.php", "wp-mail.php", "wp-settings.php", "wp-signup.php",
    "wp-trackback.php", "xmlrpc.php",
}
SUSPICIOUS_NAMES = re.compile(
    r"(compat|runtime|bridge|shell|backdoor|users\.php|install\.php|cache-|wp-[a-z]{6,}\.php)",
    re.I,
)


def wp_version(webroot):
    vf = os.path.join(webroot, "wp-includes", "version.php")
    try:
        with open(vf, "r", errors="replace") as f:
            txt = f.read(4096)
    except OSError:
        return None
    m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)", txt)
    return m.group(1) if m else None


def fetch_checksums(version, locale="en_US"):
    url = (
        "https://api.wordpress.org/core/checksums/1.0/"
        "?version=%s&locale=%s" % (version, locale)
    )
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
        print("Gagal ambil checksum WP %s: %s" % (version, e))
        return None
    if data.get("checksums"):
        return data["checksums"]
    return None


def file_md5(path):
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def is_core_scope(rel):
    if rel in WP_ROOT_FILES:
        return True
    return rel.startswith(WP_CORE_PREFIXES)


def scan_wp_root(webroot, checksums, version):
    items = []
    webroot = webroot.rstrip("/")
    seen = set()

    def add_item(path, rel, kind, detail, severity="tinggi"):
        if path in seen:
            return
        seen.add(path)
        try:
            st = os.stat(path)
        except OSError:
            return
        items.append({
            "path": path,
            "rel": rel,
            "kind": kind,
            "detail": detail,
            "severity": severity,
            "wp_version": version,
            "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime)),
            "owner": owner(path),
            "size": st.st_size,
        })

    for rel in WP_ROOT_FILES:
        p = os.path.join(webroot, rel)
        if os.path.isfile(p):
            if checksums and rel in checksums:
                md5 = file_md5(p)
                if md5 and md5 != checksums[rel]:
                    add_item(p, rel, "modified_core",
                               "Hash tidak cocok dengan core WP %s" % version)
            elif checksums and rel not in checksums:
                add_item(p, rel, "unknown_core", "File root tidak ada di manifest WP")

    for prefix in WP_CORE_PREFIXES:
        base = os.path.join(webroot, prefix.rstrip("/"))
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for name in filenames:
                if name.endswith(".md") or name == "index.html":
                    continue
                p = os.path.join(dirpath, name)
                if os.path.islink(p):
                    continue
                rel = p[len(webroot) + 1:].replace("\\", "/")
                ext = os.path.splitext(name)[1].lower()
                if rel not in checksums:
                    detail = "File tambahan — tidak ada di core WP %s" % version
                    sev = "tinggi"
                    if ext in PHP_EXT or "php" in name.lower():
                        if SUSPICIOUS_NAMES.search(rel):
                            detail += " (nama mencurigakan)"
                        add_item(p, rel, "extra_file", detail, sev)
                    elif ext in (".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2"):
                        pass  # asset tambahan — abaikan
                    else:
                        add_item(p, rel, "extra_file", detail, "sedang")
                elif ext in PHP_EXT or ext in (".js", ".css"):
                    md5 = file_md5(p)
                    if md5 and md5 != checksums[rel]:
                        add_item(p, rel, "modified_core",
                                 "Core file diubah (hash beda dari WP resmi)", "tinggi")

    mu = os.path.join(webroot, "wp-content", "mu-plugins")
    if os.path.isdir(mu):
        for name in os.listdir(mu):
            if name.startswith("."):
                continue
            p = os.path.join(mu, name)
            if not os.path.isfile(p):
                continue
            rel = "wp-content/mu-plugins/" + name
            detail = "Must-use plugin — periksa manual (sering dipakai backdoor)"
            sev = "sedang"
            if SUSPICIOUS_NAMES.search(name):
                sev = "tinggi"
                detail = "Nama mu-plugin mencurigakan — kemungkinan backdoor"
            add_item(p, rel, "mu_plugin", detail, sev)

    return items


def do_wpcore(target):
    cfg = load_conf()
    roots, is_all = resolve_targets(cfg, target)
    all_items = []
    print("Scan WP Core anomaly: %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    print("Target: %s" % ("SEMUA DOMAIN" if is_all else target))
    print("-" * 60)
    for webroot in roots:
        if not os.path.isfile(os.path.join(webroot, "wp-config.php")):
            if not is_all:
                print("Bukan instalasi WordPress: %s" % webroot)
            continue
        ver = wp_version(webroot)
        if not ver:
            print("Lewati %s — wp-includes/version.php tidak ditemukan" % webroot)
            continue
        print("Domain: %s | WordPress %s" % (webroot, ver))
        checksums = fetch_checksums(ver)
        if not checksums:
            print("  Lewati — checksum WP tidak tersedia")
            continue
        items = scan_wp_root(webroot, checksums, ver)
        print("  -> %d file aneh / tidak standar" % len(items))
        all_items.extend(items)

    order = {"tinggi": 3, "sedang": 2, "rendah": 1}
    all_items.sort(key=lambda x: (-order.get(x["severity"], 0), x["path"]))
    all_items = all_items[:500]
    out = {
        "type": "wpcore",
        "target": ("ALL" if is_all else target),
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "generated_ts": int(time.time()),
        "flagged": len(all_items),
        "items": all_items,
    }
    os.makedirs(DATA, exist_ok=True)
    with open(os.path.join(DATA, "wpcore_latest.json"), "w") as f:
        json.dump(out, f)
    print("-" * 60)
    print("Selesai. Total file aneh: %d" % len(all_items))
    for it in all_items[:30]:
        print("[%s] %s — %s" % (it["kind"], it["path"], it["detail"]))


def main():
    if len(sys.argv) < 2:
        print("usage: scanner.py backdoor|newfiles|wpcore [arg] [target]")
        return 1
    mode = sys.argv[1]
    if mode == "backdoor":
        threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 6
        target = sys.argv[3] if len(sys.argv) > 3 else "ALL"
        do_backdoor(threshold, target)
    elif mode == "newfiles":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 2
        target = sys.argv[3] if len(sys.argv) > 3 else "ALL"
        do_newfiles(days, target)
    elif mode == "wpcore":
        target = sys.argv[2] if len(sys.argv) > 2 else "ALL"
        do_wpcore(target)
    else:
        print("mode tidak dikenal: %s" % mode)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
