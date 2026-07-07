#!/usr/bin/env python3
"""Malware Scan & Backdoor Panel (ClamAV + maldet + ImunifyAV) - v5 Bootstrap UI.
Per-domain scans, background jobs, quarantine + restore, whitelist on/off.
ImunifyAV scan + panel karantina (karena Imunify gratis tidak auto-clean).
Stdlib only. HTTPS + Basic Auth.
"""
import os
import ssl
import json
import base64
import subprocess
import time
import glob
import shutil
import pwd
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

BASE = "/usr/local/maldetect-panel"
JOBS = os.path.join(BASE, "jobs")
DATA = os.path.join(BASE, "data")
QSTORE = os.path.join(BASE, "quar_store")
CONF = os.path.join(BASE, "panel.conf")
CERT = os.path.join(BASE, "panel.pem")
WL_FILE = os.path.join(DATA, "whitelist.json")
QM_FILE = os.path.join(DATA, "quarantine.json")
MALDET = "/usr/local/sbin/maldet"
MALDET_SESS = "/usr/local/maldetect/sess"
ALLOWED_PREFIX = ("/home/", "/tmp/", "/var/tmp/")

cfg = {
    "USERNAME": "scanadmin", "PASSWORD": "changeme", "PORT": "9793",
    "DOMAIN_PATH": "/home/a-listfilm.com/public_html",
    "SCAN_LOG": "/root/maldet_scan.log", "WEB_ROOTS": "/home/*/public_html",
}
try:
    with open(CONF) as f:
        for line in f:
            line = line.strip()
            if line and "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
except FileNotFoundError:
    pass

USERNAME = cfg["USERNAME"]
PASSWORD = cfg["PASSWORD"]
PORT = int(cfg["PORT"])

for d in (JOBS, DATA, QSTORE):
    os.makedirs(d, exist_ok=True)


def run(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:
        return "error: %s" % e


def read_json(path, default=None):
    try:
        return json.load(open(path))
    except Exception:
        return default


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def tail_bytes(path, nbytes=60000):
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - nbytes))
            return f.read().decode("utf-8", "replace")
    except OSError:
        return ""


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def list_domains():
    out = []
    for pat in cfg["WEB_ROOTS"].split(","):
        for p in glob.glob(pat.strip()):
            try:
                name = p.split("/home/", 1)[1].split("/")[0]
            except Exception:
                name = p
            out.append({"name": name, "path": p})
    out.sort(key=lambda x: x["name"])
    return out


# ---------- jobs ----------
def new_job(kind, title, cmd):
    jid = time.strftime("%y%m%d-%H%M%S") + "-" + kind
    logf = os.path.join(JOBS, jid + ".log")
    wrapper = cmd + '\necho "__EXIT__:$?"'
    lf = open(logf, "wb")
    proc = subprocess.Popen(["bash", "-lc", wrapper], stdout=lf, stderr=lf,
                            stdin=subprocess.DEVNULL, start_new_session=True)
    write_json(os.path.join(JOBS, jid + ".meta"),
               {"id": jid, "kind": kind, "title": title,
                "started": int(time.time()), "pid": proc.pid})
    return jid


def job_state(meta, logtail):
    if "__EXIT__:" in logtail:
        try:
            code = int(logtail.rsplit("__EXIT__:", 1)[1].split()[0])
        except Exception:
            code = -1
        return ("selesai" if code == 0 else "gagal"), code
    if pid_alive(meta.get("pid", -1)):
        return "berjalan", None
    return "terhenti", None


def list_jobs():
    out = []
    for mf in glob.glob(os.path.join(JOBS, "*.meta")):
        meta = read_json(mf)
        if not meta:
            continue
        tail = tail_bytes(os.path.join(JOBS, meta["id"] + ".log"), 4000)
        status, code = job_state(meta, tail)
        last = ""
        for ln in tail.strip().splitlines()[::-1]:
            if ln.strip() and not ln.startswith("__EXIT__"):
                last = ln.strip()
                break
        out.append({"id": meta["id"], "kind": meta["kind"], "title": meta["title"],
                    "started": meta["started"], "status": status, "exit": code,
                    "last": last[:160]})
    out.sort(key=lambda x: -x["started"])
    return out[:60]


def job_detail(jid):
    mf = os.path.join(JOBS, jid + ".meta")
    meta = read_json(mf)
    if not meta:
        return None
    tail = tail_bytes(os.path.join(JOBS, jid + ".log"), 120000)
    status, code = job_state(meta, tail)
    log = "\n".join(l for l in tail.splitlines() if not l.startswith("__EXIT__"))
    return {"meta": meta, "status": status, "exit": code, "log": log}


# ---------- whitelist ----------
def wl_load():
    return read_json(WL_FILE, [])


def wl_paths_enabled():
    return {e["path"] for e in wl_load() if e.get("enabled")}


def wl_add(path, note=""):
    wl = wl_load()
    for e in wl:
        if e["path"] == path:
            e["enabled"] = True
            write_json(WL_FILE, wl)
            return {"ok": True}
    wl.append({"path": path, "enabled": True, "note": note,
               "added": time.strftime("%Y-%m-%d %H:%M")})
    write_json(WL_FILE, wl)
    return {"ok": True}


def wl_toggle(path):
    wl = wl_load()
    for e in wl:
        if e["path"] == path:
            e["enabled"] = not e.get("enabled")
            write_json(WL_FILE, wl)
            return {"ok": True, "enabled": e["enabled"]}
    return {"error": "tidak ditemukan"}


def wl_remove(path):
    wl = [e for e in wl_load() if e["path"] != path]
    write_json(WL_FILE, wl)
    return {"ok": True}


# ---------- quarantine ----------
def qm_load():
    return read_json(QM_FILE, [])


def quarantine(path, reason=""):
    if not any(path.startswith(a) for a in ALLOWED_PREFIX):
        return {"error": "path di luar area yang diizinkan"}
    if not os.path.isfile(path):
        return {"error": "file tidak ada"}
    if path in wl_paths_enabled():
        return {"error": "file ada di whitelist (diizinkan) - tidak dikarantina"}
    try:
        st = os.lstat(path)
        qid = time.strftime("%y%m%d-%H%M%S") + "-" + os.path.basename(path)
        stored = os.path.join(QSTORE, qid)
        shutil.move(path, stored)
        os.chmod(stored, 0)
        warning = None
        if os.path.lexists(path):
            try:
                os.remove(path)
            except Exception:
                pass
        if os.path.isfile(path):
            warning = (
                "File dibuat ulang oleh malware setelah karantina. "
                "Hapus sumber infeksi (plugin wp-compat / backdoor lain) lalu gunakan Sweep."
            )
        entry = {"id": qid, "orig": path, "stored": stored, "size": st.st_size,
                 "mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid,
                 "at": time.strftime("%Y-%m-%d %H:%M"), "reason": reason}
        qm = qm_load()
        qm.append(entry)
        write_json(QM_FILE, qm)
        # Sinkronkan dengan ImunifyAV: hapus dari malicious list setelah karantina
        run("python3 %s/imavscan.py remove-listed '%s' 2>/dev/null" % (
            BASE, path.replace("'", "'\\''")))
        out = {"ok": True, "id": qid, "gone": not os.path.isfile(path)}
        if warning:
            out["warning"] = warning
        return out
    except Exception as e:
        return {"error": str(e)}


def quarantine_sweep():
    """Hapus ulang file yang sudah dikarantina tapi muncul lagi (malware persistence)."""
    removed, errors = [], []
    for e in qm_load():
        p = e.get("orig", "")
        if os.path.isfile(p):
            try:
                os.remove(p)
                removed.append(p)
            except Exception as ex:
                errors.append({"path": p, "error": str(ex)})
    return {"ok": True, "removed": removed, "count": len(removed), "errors": errors}


def quarantine_recreated():
    return [e for e in qm_load() if os.path.isfile(e.get("orig", ""))]


def restore(qid):
    qm = qm_load()
    entry = next((e for e in qm if e["id"] == qid), None)
    if not entry:
        return {"error": "entri tidak ditemukan"}
    if os.path.exists(entry["orig"]):
        return {"error": "file asli sudah ada lagi di lokasi tujuan"}
    try:
        os.makedirs(os.path.dirname(entry["orig"]), exist_ok=True)
        shutil.move(entry["stored"], entry["orig"])
        os.chmod(entry["orig"], entry.get("mode", 0o644))
        try:
            os.chown(entry["orig"], entry.get("uid", 0), entry.get("gid", 0))
        except Exception:
            pass
        write_json(QM_FILE, [e for e in qm if e["id"] != qid])
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


def delete_forever(qid):
    qm = qm_load()
    entry = next((e for e in qm if e["id"] == qid), None)
    if not entry:
        return {"error": "entri tidak ditemukan"}
    try:
        if os.path.exists(entry["stored"]):
            os.remove(entry["stored"])
        write_json(QM_FILE, [e for e in qm if e["id"] != qid])
        return {"ok": True}
    except Exception as e:
        return {"error": str(e)}


# ---------- status & findings ----------
def get_status():
    d = {}
    d["clamav_version"] = run("clamscan --version").strip().split("/")[0]
    d["clamdb"] = run("sigtool --info /var/lib/clamav/daily.cvd 2>/dev/null | grep -iE 'version|build time'").strip().replace("\n", " | ")
    d["maldet_version"] = run("%s --version 2>/dev/null | head -1" % MALDET).strip()
    d["maldet_sigs"] = run("wc -l < /usr/local/maldetect/sigs/md5.dat 2>/dev/null").strip()
    d["scan_running"] = "YES" if run("pgrep -f 'maldet .*-a ' | head -1").strip() else "no"
    d["mem"] = run("free -h | awk '/Mem/{print $3\" / \"$2}'").strip()
    d["disk"] = run("df -h / | awk 'NR==2{print $3\" / \"$2\" (\"$5\")\"}'").strip()
    d["load"] = run("uptime | sed 's/.*load average/load/'").strip()
    bd = read_json(os.path.join(DATA, "backdoor_latest.json"))
    nf = read_json(os.path.join(DATA, "newfiles_latest.json"))
    wl = wl_paths_enabled()
    if bd:
        real = [i for i in bd["items"] if i["path"] not in wl]
        d["backdoor_flagged"] = len(real)
        d["backdoor_when"] = bd.get("generated")
        d["backdoor_target"] = bd.get("target")
    else:
        d["backdoor_flagged"] = None
        d["backdoor_when"] = None
        d["backdoor_target"] = None
    d["newfiles_found"] = nf.get("found") if nf else None
    d["newfiles_when"] = nf.get("generated") if nf else None
    d["quarantined"] = len(qm_load())
    d["whitelisted"] = len([e for e in wl_load() if e.get("enabled")])
    d["malware"] = malware_summary()
    rk = read_json(os.path.join(DATA, "rkhunter_latest.json"))
    if rk:
        d["rkhunter_version"] = run("rkhunter --version 2>/dev/null | head -1").strip()
        d["rkhunter_when"] = rk.get("generated")
        d["rkhunter_warnings"] = rk.get("real_warnings")
        d["rkhunter_high"] = rk.get("high")
        d["rkhunter_scanning"] = rkhunter_running()
    else:
        d["rkhunter_version"] = run("rkhunter --version 2>/dev/null | head -1").strip()
        d["rkhunter_when"] = None
        d["rkhunter_warnings"] = None
        d["rkhunter_high"] = None
        d["rkhunter_scanning"] = rkhunter_running()
    aide = read_json(os.path.join(DATA, "aide_latest.json"))
    d["aide_version"] = run("aide --version 2>/dev/null | head -1").strip()
    d["aide_baseline"] = "YES" if run("test -f /var/lib/aide/aide.db && echo yes").strip() == "yes" else "no"
    if aide:
        d["aide_when"] = aide.get("generated")
        d["aide_changes"] = aide.get("real_changes")
        d["aide_clean"] = aide.get("clean")
    else:
        d["aide_when"] = None
        d["aide_changes"] = None
        d["aide_clean"] = None
    d["aide_scanning"] = "YES" if run("pgrep -f '[a]ide --check' | head -1").strip() else "no"
    lyn = read_json(os.path.join(DATA, "lynis_latest.json"))
    d["lynis_version"] = run("lynis --version 2>/dev/null | head -1").strip()
    if lyn:
        d["lynis_when"] = lyn.get("generated")
        d["lynis_score"] = lyn.get("hardening_score")
        d["lynis_warnings"] = lyn.get("warnings")
    else:
        d["lynis_when"] = None
        d["lynis_score"] = None
        d["lynis_warnings"] = None
    d["lynis_scanning"] = "YES" if run("pgrep -f '[l]ynis audit' | head -1").strip() else "no"
    im = imunify_summary()
    d["imunify_installed"] = im.get("installed", False)
    d["imunify_version"] = im.get("version", "")
    d["imunify_when"] = im.get("generated")
    d["imunify_count"] = im.get("count", 0)
    d["imunify_scanning"] = "YES" if run("pgrep -f '[i]munify.*malware' | head -1").strip() else "no"
    return d


def rkhunter_running():
    # pgrep -f mencocokkan command-line-nya sendiri; pakai [r] agar tidak self-match.
    return "YES" if run("pgrep -f '[r]khunter --check' | head -1").strip() else "no"


def wpusers_cmd(action, webroot, uid=""):
    esc = webroot.replace("'", "'\\''")
    cmd = "python3 %s/wpusers.py %s '%s'" % (BASE, action, esc)
    if uid:
        cmd += " %s" % int(uid)
    out = run(cmd, timeout=45)
    try:
        return json.loads(out)
    except Exception:
        return {"error": (out or "gagal parse wpusers")[:300]}


def fileinspect_cmd(action, path):
    esc = path.replace("'", "'\\''")
    out = run("python3 %s/fileinspect.py %s '%s'" % (BASE, action, esc), timeout=25)
    try:
        data = json.loads(out)
    except Exception:
        return {"error": (out or "gagal parse fileinspect")[:300]}
    if action == "detail" and "error" not in data:
        bd = read_json(os.path.join(DATA, "backdoor_latest.json"))
        if bd:
            for it in bd.get("items", []):
                if it.get("path") == path:
                    data["score"] = it.get("score")
                    data["indicators"] = it.get("indicators", [])
                    data["snippet"] = it.get("snippet", "")
                    break
        mal = malware_summary()
        for h in mal.get("hits", []):
            if h.get("path") == path:
                data["malware_sig"] = h.get("sig")
                break
    return data


def imunify_summary():
    data = read_json(os.path.join(DATA, "imunify_latest.json"), {})
    if not data:
        st = run("python3 %s/imavscan.py status 2>/dev/null" % BASE).strip()
        try:
            info = json.loads(st)
        except Exception:
            info = {}
        return {
            "installed": info.get("installed", False),
            "version": info.get("version", ""),
            "generated": None,
            "count": 0,
            "items": [],
        }
    return {
        "installed": True,
        "version": data.get("version", ""),
        "generated": data.get("generated"),
        "count": data.get("count", len(data.get("items", []))),
        "items": data.get("items", []),
        "error": data.get("error"),
    }


def malware_summary():
    hits = []
    files = sorted(glob.glob(os.path.join(MALDET_SESS, "session.hits.*")),
                   key=os.path.getmtime, reverse=True)
    if files:
        seen = set()
        for line in open(files[0], "r", errors="replace"):
            line = line.strip()
            if " : " in line:
                sig, _, path = line.partition(" : ")
                key = (sig.strip(), path.strip())
                if key not in seen:
                    seen.add(key)
                    hits.append({"sig": sig.strip(), "path": path.strip()})
    summary = ""
    for lg in ("/root/maldet_fullscan.log", cfg["SCAN_LOG"]):
        s = run("grep 'scan completed' %s 2>/dev/null | tail -1" % lg).strip()
        if s:
            summary = s
            break
    return {"hits": hits, "summary": summary}


def findings():
    bd = read_json(os.path.join(DATA, "backdoor_latest.json"))
    nf = read_json(os.path.join(DATA, "newfiles_latest.json"))
    wl = wl_paths_enabled()
    qpaths = {e["orig"] for e in qm_load()}
    recreated = {e["orig"] for e in quarantine_recreated()}
    if bd:
        for it in bd["items"]:
            it["whitelisted"] = it["path"] in wl
            it["quarantined"] = it["path"] in qpaths
            it["recreated"] = it["path"] in recreated
    rk = read_json(os.path.join(DATA, "rkhunter_latest.json"))
    aide = read_json(os.path.join(DATA, "aide_latest.json"))
    lyn = read_json(os.path.join(DATA, "lynis_latest.json"))
    im = imunify_summary()
    wl = wl_paths_enabled()
    qpaths = {e["orig"] for e in qm_load()}
    if im.get("items"):
        for it in im["items"]:
            p = it.get("path", "")
            it["whitelisted"] = p in wl
            it["quarantined"] = p in qpaths
    return {"backdoor": bd, "newfiles": nf, "malware": malware_summary(),
            "imunify": im, "rkhunter": rk, "aide": aide, "lynis": lyn,
            "whitelist": wl_load(), "quarantine": qm_load(),
            "quarantine_recreated": quarantine_recreated()}


# ---------- HTML (loaded from index.html) ----------
def load_page():
    path = os.path.join(BASE, "index.html")
    with open(path, encoding="utf-8") as f:
        return f.read()


PAGE = load_page()


class Handler(BaseHTTPRequestHandler):
    server_version = "ScanPanel"

    def _auth_ok(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            return False
        try:
            u, _, p = base64.b64decode(h[6:]).decode("utf-8", "ignore").partition(":")
            return u == USERNAME and p == PASSWORD
        except Exception:
            return False

    def _need_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Panel Keamanan"')
        self.end_headers()
        self.wfile.write(b"Butuh login")

    def _send(self, body, ctype="text/html; charset=utf-8", code=200):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _json(self, obj, code=200):
        self._send(json.dumps(obj), "application/json; charset=utf-8", code)

    def log_message(self, *a):
        pass

    def do_GET(self):
        if not self._auth_ok():
            return self._need_auth()
        u = urlparse(self.path)
        p = u.path
        if p in ("/", "/index.html"):
            return self._send(PAGE)
        if p == "/api/status":
            return self._json(get_status())
        if p == "/api/domains":
            return self._json({"domains": list_domains()})
        if p == "/api/jobs":
            return self._json({"jobs": list_jobs()})
        if p == "/api/job":
            return self._json(job_detail(parse_qs(u.query).get("id", [""])[0]) or {"error": "not found"})
        if p == "/api/findings":
            return self._json(findings())
        if p == "/api/wpusers":
            dom = parse_qs(u.query).get("domain", [cfg["DOMAIN_PATH"]])[0]
            return self._json(wpusers_cmd("list", dom))
        if p == "/api/file/detail":
            fp = parse_qs(u.query).get("path", [""])[0]
            return self._json(fileinspect_cmd("detail", fp) if fp else {"error": "path kosong"})
        if p == "/api/file/probe":
            fp = parse_qs(u.query).get("path", [""])[0]
            return self._json(fileinspect_cmd("probe", fp) if fp else {"error": "path kosong"})
        return self._send("404", code=404)

    def do_POST(self):
        if not self._auth_ok():
            return self._need_auth()
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        p = u.path

        def g(name, default=""):
            return qs.get(name, [default])[0]

        if p == "/api/run/backdoor":
            th = g("threshold", "8")
            th = str(int(th)) if th.isdigit() else "8"
            dom = g("domain", "ALL") or "ALL"
            label = "semua" if dom == "ALL" else dom.split("/")[2] if "/home/" in dom else dom
            jid = new_job("backdoor", "Scan Backdoor [%s] th=%s" % (label, th),
                          "python3 %s/scanner.py backdoor %s '%s'" % (BASE, th, dom))
            return self._json({"id": jid, "title": "Scan Backdoor"})
        if p == "/api/run/malware":
            dom = g("domain", "ALL") or "ALL"
            if dom == "ALL":
                target = "$(ls -d /home/*/public_html 2>/dev/null | paste -sd, -)"
                label = "semua"
            else:
                target = "'%s'" % dom
                label = dom.split("/")[2] if "/home/" in dom else dom
            jid = new_job("malware", "Scan Malware [%s]" % label, "maldet -a %s" % target)
            return self._json({"id": jid, "title": "Scan Malware"})
        if p == "/api/run/imunify":
            dom = g("domain", "ALL") or "ALL"
            if dom == "ALL":
                cmd = "python3 %s/imavscan.py scan-all" % BASE
                label = "semua"
            else:
                esc = dom.replace("'", "'\\''")
                cmd = "python3 %s/imavscan.py scan '%s'" % (BASE, esc)
                label = dom.split("/")[2] if "/home/" in dom else dom
            jid = new_job("imunify", "ImunifyAV Scan [%s]" % label, cmd)
            return self._json({"id": jid, "title": "ImunifyAV Scan"})
        if p == "/api/run/imunifysync":
            jid = new_job("imunifysync", "Sync ImunifyAV Malicious List",
                          "python3 %s/imavscan.py sync" % BASE)
            return self._json({"id": jid, "title": "Sync ImunifyAV"})
        if p == "/api/run/synergy":
            dom = g("domain", "ALL") or "ALL"
            th = g("threshold", "8")
            th = str(int(th)) if th.isdigit() else "8"
            if dom == "ALL":
                cmd = (
                    "for d in /home/*/public_html; do "
                    "/usr/local/maldetect-panel/synergy-scan.sh \"$d\" %s; done"
                ) % th
                label = "semua"
            else:
                esc = dom.replace("'", "'\\''")
                cmd = "/usr/local/maldetect-panel/synergy-scan.sh '%s' %s" % (esc, th)
                label = dom.split("/")[2] if "/home/" in dom else dom
            jid = new_job("synergy", "Scan Sinergi [%s]" % label, cmd)
            return self._json({"id": jid, "title": "Scan Sinergi"})
        if p == "/api/run/newfiles":
            days = g("days", "3")
            days = str(int(days)) if days.isdigit() else "3"
            dom = g("domain", "ALL") or "ALL"
            label = "semua" if dom == "ALL" else dom.split("/")[2] if "/home/" in dom else dom
            jid = new_job("newfiles", "File Baru [%s] %sh" % (label, days),
                          "python3 %s/scanner.py newfiles %s '%s'" % (BASE, days, dom))
            return self._json({"id": jid, "title": "Deteksi File Baru"})
        if p == "/api/run/updatedb":
            jid = new_job("updatedb", "Update Database ClamAV",
                          "/usr/local/bin/clamav-db-update.sh; echo selesai")
            return self._json({"id": jid, "title": "Update Database ClamAV"})
        if p == "/api/run/rkhunter":
            jid = new_job("rkhunter", "Scan Sistem (rkhunter)",
                          "python3 %s/rkscan.py check" % BASE)
            return self._json({"id": jid, "title": "Scan Sistem (rkhunter)"})
        if p == "/api/run/rkupdate":
            jid = new_job("rkupdate", "Update Database rkhunter",
                          "python3 %s/rkscan.py update" % BASE)
            return self._json({"id": jid, "title": "Update Database rkhunter"})
        if p == "/api/run/aide":
            jid = new_job("aide", "Cek Integritas File (AIDE)",
                          "python3 %s/aidescan.py check" % BASE)
            return self._json({"id": jid, "title": "Scan AIDE"})
        if p == "/api/run/aideinit":
            jid = new_job("aideinit", "Buat Baseline AIDE",
                          "python3 %s/aidescan.py init" % BASE)
            return self._json({"id": jid, "title": "Baseline AIDE"})
        if p == "/api/run/lynis":
            jid = new_job("lynis", "Audit Keamanan (Lynis)",
                          "python3 %s/lynisscan.py audit" % BASE)
            return self._json({"id": jid, "title": "Audit Lynis"})
        if p == "/api/run/quarantine-bulk":
            source = g("source", "all") or "all"
            if source not in ("imunify", "backdoor", "malware", "all"):
                return self._json({"error": "source tidak valid"}, 400)
            dom = g("domain", "ALL") or "ALL"
            th = g("threshold", "12")
            th = str(int(th)) if th.isdigit() else "12"
            esc_dom = dom.replace("'", "'\\''")
            label_src = {"imunify": "ImunifyAV", "backdoor": "Backdoor",
                         "malware": "maldet", "all": "Semua"}[source]
            label_dom = "semua" if dom == "ALL" else (
                dom.split("/")[2] if "/home/" in dom else dom)
            cmd = (
                "python3 %s/quarantine_bulk.py '%s' '%s' %s"
                % (BASE, source, esc_dom, th)
            )
            jid = new_job(
                "quar-bulk",
                "Bulk Karantina [%s / %s]" % (label_src, label_dom),
                cmd,
            )
            return self._json({"id": jid, "title": "Bulk Karantina"})
        if p == "/api/quarantine/add":
            return self._json(quarantine(g("path"), g("reason")))
        if p == "/api/quarantine/restore":
            return self._json(restore(g("id")))
        if p == "/api/quarantine/delete":
            return self._json(delete_forever(g("id")))
        if p == "/api/quarantine/sweep":
            return self._json(quarantine_sweep())
        if p == "/api/whitelist/add":
            return self._json(wl_add(g("path"), g("note")))
        if p == "/api/whitelist/toggle":
            return self._json(wl_toggle(g("path")))
        if p == "/api/whitelist/remove":
            return self._json(wl_remove(g("path")))
        if p == "/api/wpuser/deactivate":
            return self._json(wpusers_cmd("deactivate", g("domain", cfg["DOMAIN_PATH"]), g("id")))
        if p == "/api/wpuser/quarantine":
            return self._json(wpusers_cmd("quarantine", g("domain", cfg["DOMAIN_PATH"]), g("id")))
        return self._json({"error": "aksi tidak dikenal"}, 404)


def main():
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print("Panel Keamanan aktif di https://0.0.0.0:%d" % PORT)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
