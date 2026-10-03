#!/usr/bin/env python3
"""Build a run ledger from live Elasticsearch evidence (generic, by run id).

Discovers the S1..S7 signature events inside the run window, stores rich join
fields per ref (entity / parent entity / file path / destination / registry /
WMI references), and indexes the run artifacts. Credentials: environment only.
Usage: python scripts/build_ledger_run.py RUN-YYYYMMDD-NN   (ES_URL/ES_USER/ES_PASS)
Guest-side svhw.ps1 hash (module anchor) must be passed via GUEST_SVHW_SHA256.
"""
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ES = os.environ["ES_URL"].rstrip("/")
USER = os.environ.get("ES_USER", "elastic")
PASS = os.environ["ES_PASS"]
SYS = ".ds-logs-windows.sysmon_operational-*"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()
RUN = sys.argv[1] if len(sys.argv) > 1 else ""
if not re.match(r"^RUN-[0-9]{8}-[0-9]{2,}$", RUN):
    raise SystemExit("provide a run id RUN-YYYYMMDD-NN")
GUEST_HASH = os.environ.get("GUEST_SVHW_SHA256", "")


def post(url, body):
    r = urllib.request.Request(url, data=json.dumps(body).encode(),
                               headers={"Authorization": AUTH, "Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=30, context=CTX) as resp:
        return json.load(resp)


def search(filters, size=12):
    return post(f"{ES}/{SYS}/_search",
                {"size": size, "query": {"bool": {"filter": filters}},
                 "sort": [{"@timestamp": "asc"}]})["hits"]["hits"]


def gp(d, p):
    for k in p.split("."):
        if not isinstance(d, dict) or k not in d:
            return None
        d = d[k]
    return d


def clean(v):
    if v is None:
        return None
    return v.strip().strip('"') if isinstance(v, str) else v


def canon(p):
    return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest().upper()


def raw(p):
    return hashlib.sha256(p.read_bytes()).hexdigest().upper()


def ref(s):
    wl = s.get("winlog") or {}
    ed = wl.get("event_data") or {}
    reg = s.get("registry") or {}
    head = (s.get("message") or "").splitlines()[0][:110] if s.get("message") else ""
    return {"kind": "event", "es_id": None, "ts": s.get("@timestamp"),
            "event": str(gp(s, "event.code") or ""), "detail": head,
            "process_name": clean(gp(s, "process.name")),
            "entity_id": clean(gp(s, "process.entity_id")),
            "parent_entity_id": clean(gp(s, "process.parent.entity_id")),
            "user": clean(gp(s, "user.name")),
            "file_path": clean(gp(s, "file.path")),
            "file_name": clean(gp(s, "file.name")),
            "dst_ip": clean(gp(s, "destination.ip")),
            "dst_port": clean(gp(s, "destination.port")),
            "registry_path": clean(reg.get("path")),
            "registry_value": clean(reg.get("value")),
            "wmi_name": clean(ed.get("Name")), "wmi_operation": clean(ed.get("Operation")),
            "wmi_consumer": clean(ed.get("Consumer")), "wmi_filter": clean(ed.get("Filter"))}


def with_ids(refs, hits):
    for r, h in zip(refs, hits):
        r["es_id"] = h["_id"]
    return refs


base = [{"term": {"host.name": "wmi"}}]
s1 = search(base + [{"term": {"event.code": "1"}}, {"wildcard": {"message": "*setup.bat*"}}], 2)
W0 = s1[0]["_source"]["@timestamp"] if s1 else None
window = {"gte": W0, "lte": "now+1m"}  # verifier uses ledger ts; ES re-verify uses es_id only
reg = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "13"}},
                     {"term": {"process.name": "reg.exe"}}], 4)
fod = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "1"}},
                     {"term": {"process.name": "fodhelper.exe"}}], 2)
wsc = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "1"}},
                     {"term": {"process.name": "wscript.exe"}}], 2)
psi = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "1"}},
                     {"term": {"process.name": "powershell.exe"}},
                     {"wildcard": {"process.command_line": "*install.ps1*"}}], 2)
svh = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "11"}},
                     {"wildcard": {"file.name": "svhw.ps1"}}], 2)
e19 = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "19"}},
                     {"term": {"winlog.event_data.Operation": "Created"}}], 2)
e20 = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "20"}},
                     {"term": {"winlog.event_data.Operation": "Created"}}], 2)
e21 = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "21"}},
                     {"term": {"winlog.event_data.Operation": "Created"}}], 2)
ntp = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "1"}},
                     {"term": {"process.name": "notepad.exe"}}], 2)
wps = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "1"}},
                     {"term": {"process.parent.name": "WmiPrvSE.exe"}}], 2)
arp = post(f"{ES}/{SYS}/_search",
           {"size": 2, "query": {"bool": {"must": [{"query_string": {"query": 'message:"arp"'}}],
                                   "filter": base + [{"range": {"@timestamp": {"gte": W0}}},
                                                     {"term": {"event.code": "1"}}]}},
            "sort": [{"@timestamp": "asc"}]})["hits"]["hits"]
info = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "11"}},
                      {"term": {"file.name": "info.txt"}}], 2)
manf = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "11"}},
                      {"term": {"file.name": "_manifest.txt"}}], 2)
zcr = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "11"}},
                     {"term": {"file.name": "wdmp.zip"}}], 2)
cur1 = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "1"}},
                      {"term": {"process.name": "curl.exe"}}], 4)
cur3 = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "3"}},
                      {"term": {"process.name": "curl.exe"}}], 3)
ps3 = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "3"}},
                     {"terms": {"process.name": ["powershell.exe"]}}], 3)
d23 = search(base + [{"range": {"@timestamp": {"gte": W0}}}, {"term": {"event.code": "23"}},
                     {"wildcard": {"file.name": "wdmp.zip"}}], 2)

svh_refs = with_ids([ref(h["_source"]) for h in svh], svh)
if svh_refs and GUEST_HASH:
    svh_refs[0]["file_hash"] = GUEST_HASH.upper()
    svh_refs[0]["file_hash_provenance"] = "guest probe; EID11 event carries no Hashes on this stack"

stages = [
    {"stage": "S1", "host": "wmi", "account": "WMI\\Duc", "status": "PASS",
     "input_artifacts": [], "output_artifacts": [],
     "evidence_refs": with_ids([ref(s1[0]["_source"])], s1[:1]),
     "notes": "operator action: setup.bat launched via vmrun (declared; session 0, High integrity)"},
    {"stage": "S2", "host": "wmi", "account": "WMI\\Duc", "status": "PASS",
     "input_artifacts": [], "output_artifacts": [],
     "evidence_refs": with_ids([ref(h["_source"]) for h in reg[:2] + fod + wsc + psi], reg[:2] + fod + wsc + psi),
     "notes": "registry->fodhelper TEMPORAL/CONTEXTUAL; ancestry verifier-checked"},
    {"stage": "S3", "host": "wmi", "account": "WMI\\Duc", "status": "PASS",
     "input_artifacts": ["ART-01-02"], "output_artifacts": [],
     "evidence_refs": svh_refs + with_ids([ref(h["_source"]) for h in e19[:1] + e20[:1] + e21[:1]],
                                          e19[:1] + e20[:1] + e21[:1]),
     "notes": "registration sequence 19/20/21 all Created (gate PASS); binding refs verifier-checked; module integrity via guest hash"},
    {"stage": "S4", "host": "wmi", "account": "NT AUTHORITY\\SYSTEM", "status": "PASS",
     "input_artifacts": [], "output_artifacts": [],
     "evidence_refs": with_ids([ref(h["_source"]) for h in ntp[:1] + wps[:1]], ntp[:1] + wps[:1]),
     "notes": "activation: console notepad trigger; consumer under WmiPrvSE as SYSTEM"},
    {"stage": "S5", "host": "wmi", "account": "NT AUTHORITY\\SYSTEM", "status": "PASS",
     "input_artifacts": [], "output_artifacts": ["ART-06-01"],
     "evidence_refs": with_ids([ref(h["_source"]) for h in arp[:1] + info[:1] + manf[:1]], arp[:1] + info[:1] + manf[:1]),
     "notes": "in-process queries not independently evidenced; ARP parent entity == consumer entity (verifier)"},
    {"stage": "S6", "host": "wmi", "account": "NT AUTHORITY\\SYSTEM", "status": "PASS",
     "input_artifacts": ["ART-06-01"], "output_artifacts": ["ART-07-01"],
     "evidence_refs": with_ids([ref(h["_source"]) for h in zcr[:1] + cur1[:2] + cur3[:1] + ps3[:1]],
                               zcr[:1] + cur1[:2] + cur3[:1] + ps3[:1]) +
         [{"kind": "receipt", "artifact": "ART-07-01-*.json",
           "detail": "sink receipt (server-side); raw sha256 + manifest canonical hash"}],
     "notes": "archive create by consumer entity; curl E1/E3 entity-owned; receipt proves transfer"},
    {"stage": "S7", "host": "wmi", "account": "NT AUTHORITY\\SYSTEM", "status": "PASS",
     "input_artifacts": [], "output_artifacts": ["ART-08-01"],
     "evidence_refs": with_ids([ref(d23[0]["_source"])], d23[:1]),
     "notes": "wdmp.zip deletion; create/delete same file.path (verifier)"},
]

run_dir = ROOT / "evidence" / "runs" / RUN
idx = []
for aid, rel, prod, cons in (("ART-01-01", "payload/setup.bat", "S1", ""),
                             ("ART-01-02", "payload/consumer.ps1", "S3", "S7"),
                             ("ART-01-03", "payload/install.ps1", "S2", "S3"),
                             ("ART-06-01", "_manifest.txt", "S5", "S6"),
                             ("ART-07-01", f"ART-07-01-{RUN}.json", "S6", ""),
                             ("ART-08-01", f"ART-08-01-{RUN}.json", "S7", "")):
    p = run_dir / rel
    if not p.is_file():
        raise SystemExit(f"missing artifact {rel}")
    idx.append({"artifact_id": aid, "path": rel, "sha256": raw(p) if p.suffix.lower() == ".zip" else canon(p),
                "producer_stage": prod, "consumer_stage": cons})
ledger = {"run_id": RUN, "scenario_id": "WMI-LAB-1",
          "created_utc": (W0 or "")[:19] + "Z",  # schema: whole seconds, Z
          "secrets_policy": "no-secrets-allowed", "stages": stages, "artifact_index": idx}
out = run_dir / f"{RUN}.json"
out.write_text(json.dumps(ledger, indent=2, ensure_ascii=False), encoding="utf-8")
print("wrote", out)
print("stages:", [(s["stage"], s["status"]) for s in stages])
print("event refs:", sum(1 for s in stages for r in s["evidence_refs"] if r.get("kind") == "event"))
print("artifacts:", [(a["artifact_id"], a["sha256"][:8]) for a in idx])