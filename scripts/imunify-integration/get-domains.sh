#!/bin/bash
# Daftar domain CyberPanel (/home/*/public_html) untuk ImunifyAV standalone
python3 - <<'PY'
import json
import glob

data = {}
for pub in sorted(glob.glob("/home/*/public_html")):
    user = pub.split("/")[2]
    data[user] = {
        "document_root": pub + "/",
        "is_main": True,
        "owner": user,
    }
print(json.dumps({"data": data, "metadata": {"result": "ok"}}))
PY
