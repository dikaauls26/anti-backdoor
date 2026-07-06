#!/usr/bin/env python3
"""WordPress user audit for security panel."""
import os
import re
import json
import time
import subprocess
import shlex

DATA = "/usr/local/maldetect-panel/data"
QFILE = os.path.join(DATA, "wp_user_quarantine.json")

# Known rogue accounts from prior incident + common backdoor admin patterns.
KNOWN_BAD = {
    "adminbockup", "sabmilum", "admlnlx", "wpadmin", "wp_admin", "wordpress",
    "adminuser", "superadmin", "webadmin", "sysadmin",
}
SUSPICIOUS_RE = [
    re.compile(r"admin.*b(ack)?up", re.I),
    re.compile(r"admln", re.I),
    re.compile(r"^admin[a-z0-9]{2,8}$", re.I),
    re.compile(r"^(test|demo|hack|shell|backdoor|root|mysql)", re.I),
    re.compile(r"^[a-z]{6,10}[0-9]{1,3}$", re.I),
]


def parse_wp_config(webroot):
    path = os.path.join(webroot, "wp-config.php")
    if not os.path.isfile(path):
        return None
    txt = open(path, encoding="utf-8", errors="replace").read()

    def define_val(key):
        m = re.search(
            r"define\s*\(\s*['\"]%s['\"]\s*,\s*['\"]([^'\"]*)['\"]" % re.escape(key),
            txt,
        )
        return m.group(1) if m else None

    pm = re.search(r"\$table_prefix\s*=\s*['\"]([^'\"]*)['\"]", txt)
    db = define_val("DB_NAME")
    user = define_val("DB_USER")
    pwd = define_val("DB_PASSWORD")
    if not all([db, user, pwd is not None]):
        return None
    return {
        "webroot": webroot,
        "db": db,
        "user": user,
        "password": pwd,
        "host": define_val("DB_HOST") or "localhost",
        "prefix": pm.group(1) if pm else "wp_",
    }


def parse_role(caps):
    if not caps:
        return "unknown"
    m = re.search(r's:\d+:"([^"]+)";b:1', caps)
    if m:
        return m.group(1)
    if "administrator" in caps:
        return "administrator"
    if "editor" in caps:
        return "editor"
    if "author" in caps:
        return "author"
    if "subscriber" in caps:
        return "subscriber"
    return "other"


def mysql_query(cfg, sql):
    cmd = [
        "mysql", "-h", cfg["host"], "-u", cfg["user"],
        "-p%s" % cfg["password"], cfg["db"], "-N", "-B", "-e", sql,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            return None, (r.stderr or r.stdout or "mysql error").strip()
        return r.stdout.strip(), None
    except Exception as e:
        return None, str(e)


def mysql_exec(cfg, sql):
    out, err = mysql_query(cfg, sql)
    if err:
        return {"error": err}
    return {"ok": True, "output": out}


def qlog_load():
    try:
        return json.load(open(QFILE))
    except Exception:
        return []


def qlog_save(items):
    os.makedirs(DATA, exist_ok=True)
    tmp = QFILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(items, f)
    os.replace(tmp, QFILE)


def assess_user(u):
    reasons = []
    login = (u.get("login") or "").lower()
    email = (u.get("email") or "").lower()
    role = u.get("role") or ""

    if login in KNOWN_BAD:
        reasons.append("username dikenal mencurigakan")
    for rx in SUSPICIOUS_RE:
        if rx.search(u.get("login") or ""):
            reasons.append("pola username mencurigakan")
            break
    if role == "administrator":
        try:
            reg = time.strptime(u.get("registered", "")[:19], "%Y-%m-%d %H:%M:%S")
            age_days = (time.time() - time.mktime(reg)) / 86400
            if age_days < 30:
                reasons.append("admin baru (<30 hari)")
        except Exception:
            pass
        if re.search(r"@(mail\.ru|yandex|temp|guerrilla|10min)", email):
            reasons.append("email domain mencurigakan")
        if login != email.split("@")[0] and len(login) > 12:
            reasons.append("username panjang tidak wajar")
    if u.get("quarantined"):
        reasons.append("sudah dikarantina panel")
    if int(u.get("user_status") or 0) != 0:
        reasons.append("status user tidak aktif")

    risk = "aman"
    if reasons:
        risk = "tinggi" if (
            "username dikenal mencurigakan" in reasons
            or role == "administrator" and len(reasons) >= 2
            or "pola username mencurigakan" in reasons and role == "administrator"
        ) else "sedang"
    return risk, reasons


def list_users(webroot):
    cfg = parse_wp_config(webroot)
    if not cfg:
        return {"error": "bukan instalasi WordPress (wp-config.php tidak ditemukan)"}

    p = cfg["prefix"]
    sql = (
        "SELECT u.ID, u.user_login, u.user_email, u.user_registered, u.user_status, "
        "(SELECT meta_value FROM %susermeta WHERE user_id=u.ID AND meta_key='%scapabilities' LIMIT 1) "
        "FROM %susers u ORDER BY u.ID"
    ) % (p, p, p)
    raw, err = mysql_query(cfg, sql)
    if err:
        return {"error": err}

    qmap = {}
    for e in qlog_load():
        if e.get("webroot") == webroot:
            qmap[int(e["user_id"])] = e

    users = []
    admin_count = 0
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        uid, login, email, registered, status, caps = parts[:6]
        role = parse_role(caps)
        if role == "administrator":
            admin_count += 1
        item = {
            "id": int(uid),
            "login": login,
            "email": email,
            "registered": registered,
            "role": role,
            "user_status": int(status or 0),
            "quarantined": int(uid) in qmap,
        }
        risk, reasons = assess_user(item)
        item["risk"] = risk
        item["reasons"] = reasons
        users.append(item)

    if admin_count > 3:
        for u in users:
            if u["role"] == "administrator" and u["risk"] == "aman":
                u["risk"] = "sedang"
                u["reasons"].append("jumlah admin >3")

    suspicious = [u for u in users if u["risk"] != "aman"]
    domain = webroot.split("/home/", 1)[-1].split("/")[0] if "/home/" in webroot else webroot
    return {
        "domain": domain,
        "webroot": webroot,
        "total": len(users),
        "admins": admin_count,
        "suspicious": len(suspicious),
        "users": users,
    }


def deactivate_user(webroot, user_id):
    cfg = parse_wp_config(webroot)
    if not cfg:
        return {"error": "WordPress tidak ditemukan"}
    uid = int(user_id)
    p = cfg["prefix"]
    sql = (
        "UPDATE %susermeta SET meta_value='a:1:{s:10:\"subscriber\";b:1;}' "
        "WHERE user_id=%d AND meta_key='%scapabilities'; "
        "UPDATE %susermeta SET meta_value='0' "
        "WHERE user_id=%d AND meta_key='%suser_level';"
    ) % (p, uid, p, p, uid, p)
    res = mysql_exec(cfg, sql)
    if res.get("error"):
        return res
    return {"ok": True, "action": "deactivate", "user_id": uid}


def quarantine_user(webroot, user_id):
    cfg = parse_wp_config(webroot)
    if not cfg:
        return {"error": "WordPress tidak ditemukan"}
    uid = int(user_id)

    p = cfg["prefix"]
    info_sql = (
        "SELECT user_login, user_email FROM %susers WHERE ID=%d LIMIT 1"
    ) % (p, uid)
    raw, err = mysql_query(cfg, info_sql)
    if err:
        return {"error": err}
    if not raw:
        return {"error": "user tidak ditemukan"}
    login, email = raw.split("\t", 1)

    # Lock account: demote + unusable password hash.
    lock_hash = "$P$Bpanelquarantinehashxxxxxxxxxxxx"
    sql = (
        "UPDATE %susers SET user_pass='%s' WHERE ID=%d; "
        "UPDATE %susermeta SET meta_value='a:1:{s:10:\"subscriber\";b:1;}' "
        "WHERE user_id=%d AND meta_key='%scapabilities'; "
        "UPDATE %susermeta SET meta_value='0' "
        "WHERE user_id=%d AND meta_key='%suser_level';"
    ) % (p, lock_hash, uid, p, uid, p, p, uid, p)
    res = mysql_exec(cfg, sql)
    if res.get("error"):
        return res

    ql = qlog_load()
    ql = [e for e in ql if not (e.get("webroot") == webroot and int(e.get("user_id", 0)) == uid)]
    ql.append({
        "webroot": webroot,
        "user_id": uid,
        "login": login,
        "email": email,
        "at": time.strftime("%Y-%m-%d %H:%M"),
    })
    qlog_save(ql)
    return {"ok": True, "action": "quarantine", "user_id": uid, "login": login}


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: wpusers.py list|deactivate|quarantine <webroot> [id]"}))
        raise SystemExit(1)
    action, webroot = sys.argv[1], sys.argv[2]
    if action == "list":
        print(json.dumps(list_users(webroot)))
    elif action == "deactivate":
        print(json.dumps(deactivate_user(webroot, sys.argv[3])))
    elif action == "quarantine":
        print(json.dumps(quarantine_user(webroot, sys.argv[3])))
    else:
        print(json.dumps({"error": "aksi tidak dikenal"}))
