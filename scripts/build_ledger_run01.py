#!/usr/bin/env python3
"""Build RUN-20261003-01 ledger from live Elasticsearch evidence.

Every ref stores the real es_id + @timestamp plus the join fields the verifier
needs (process entity / parent entity / file path / destination / registry /
WMI references), so ancestry, ownership and binding/path assertions are checked
offline from the ledger and re-checked against ES by the verifier.
Credentials: environment only (ES_URL / ES_USER / ES_PASS).
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
RUN = "RUN-20261003-01"
ES = os.environ["ES_URL"].rstrip("/")
USER = os.environ.get("ES_USER", "elastic")
PASS = os.environ["ES_PASS"]
SYS = ".ds-logs-windows.sysmon_operational-*"

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()


def req(url, body):
    r = urllib.request.Request(url, data=json.dumps(body).encode(),
                               headers={"Authorization": AUTH, "Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=40, context=CTX) as resp:
        return json.load(resp)


def gp(doc, path):
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def clean(v):
    if v is None:
        return None
    if isinstance(v, str):
        return v.strip().strip('"')
    return v


# The 21 verified evidence ids (+ the archive-create E11 for C5/path equality).
REF_IDS = [
    "AaEBMN8OoLLJxo4Fkbwr",  # S1 cmd setup.bat
    "AaEBMN8OoLLJxo4FkbxH",  # S2 EID13 (Default)
    "AaEBMN8OoLLJxo4FkbxL",  # S2 EID13 DelegateExecute
    "AaEBMN8OoLLJxo4FkbxN",  # S2 fodhelper
    "AaEBMN8OoLLJxo4Fkby8",  # S2 wscript
    "AaEBMN8OoLLJxo4FkrwV",  # S2 powershell install.ps1
    "AaEBMN8OoLLJxo4Ok4eC",  # S3 EID11 svhw.ps1 write
    "AaEBMN8OoLLJxo4OlomC",  # S3 EID19
    "AaEBMN8OoLLJxo4OlomI",  # S3 EID20
    "AaEBMN8OoLLJxo4Oloma",  # S3 EID21
    "AaEBMN8OoLLJxo6t5RwS",  # S4 notepad
    "AaEBMN8OoLLJxo69_N8k",  # S4 consumer powershell (WmiPrvSE)
    "AaEBMN8OoLLJxo_OEQdW",  # S5 ARP.EXE
    "AaEBMN8OoLLJxo_OEQdp",  # S5 info.txt
    "AaEBMN8OoLLJxo_OEQeO",  # S5 _manifest.txt
    "AaEBMN8OoLLJxo_OFAgY",  # S6 EID11 wdmp.zip CREATE
    "AaEBMN8OoLLJxo_OFAid",  # S6 curl E1 (zip upload)
    "AaEBMN8OoLLJxo_OFAju",  # S6 curl E1 (manifest upload)
    "AaEBMN8OoLLJxo_MDTG7",  # S6 curl E3
    "AaEBMN8OoLLJxo_MDzFL",  # S6 powershell status E3
    "AaEBMN8OoLLJxo_bHnHx",  # S7 EID23 wdmp.zip delete
]

docs = {}
for i in range(0, len(REF_IDS), 50):
    batch = REF_IDS[i:i + 50]
    r = req(f"{ES}/{SYS}/_search", {"size": 50, "query": {"ids": {"values": batch}}})
    for h in r["hits"]["hits"]:
        docs[h["_id"]] = h["_source"]


def ref(es_id, detail_extra=""):
    s = docs[es_id]
    wl = s.get("winlog") or {}
    ed = wl.get("event_data") or {}
    reg = s.get("registry") or {}
    head = (s.get("message") or "").splitlines()[0][:110] if s.get("message") else ""
    return {
        "kind": "event", "es_id": es_id, "ts": s.get("@timestamp"),
        "event": str(gp(s, "event.code") or ""),
        "detail": head + (" " + detail_extra if detail_extra else ""),
        "process_name": clean(gp(s, "process.name")),
        "entity_id": clean(gp(s, "process.entity_id")),
        "parent_entity_id": clean(gp(s, "process.parent.entity_id")),
        "user": clean(gp(s, "user.name")) or clean(gp(s, "winlog.user.name")),
        "file_path": clean(gp(s, "file.path")),
        "file_name": clean(gp(s, "file.name")),
        "dst_ip": clean(gp(s, "destination.ip")),
        "dst_port": clean(gp(s, "destination.port")),
        "registry_path": clean(reg.get("path")),
        "registry_value": clean(reg.get("value")),
        "wmi_name": clean(ed.get("Name")),
        "wmi_operation": clean(ed.get("Operation")),
        "wmi_consumer": clean(ed.get("Consumer")),
        "wmi_filter": clean(ed.get("Filter")),
    }


# S3 module-integrity value captured by guest probe (09:56Z); the EID11 doc carries
# no Hashes on this stack - provenance recorded in the ref detail.
GUEST_SVHW_SHA256 = "6B90E6F8125A48E63DF9CCA193621A3105E523423ABEA02542D764A379E8C80A"

s3_write = ref("AaEBMN8OoLLJxo4Ok4eC")
s3_write["file_hash"] = GUEST_SVHW_SHA256
s3_write["file_hash_provenance"] = "guest probe 2026-10-03T09:56Z; the EID11 event carries no Hashes on this stack"
stages = [
    {"stage": "S1", "host": "wmi", "account": "WMI\\Duc", "status": "PASS",
     "input_artifacts": [], "output_artifacts": [],
     "evidence_refs": [ref("AaEBMN8OoLLJxo4Fkbwr")],
     "notes": "operator action: setup.bat launched via vmrun (declared; session 0, High integrity)"},
    {"stage": "S2", "host": "wmi", "account": "WMI\\Duc", "status": "PASS",
     "input_artifacts": [], "output_artifacts": [],
     "evidence_refs": [ref("AaEBMN8OoLLJxo4FkbxH"), ref("AaEBMN8OoLLJxo4FkbxL"),
                       ref("AaEBMN8OoLLJxo4FkbxN"), ref("AaEBMN8OoLLJxo4Fkby8"),
                       ref("AaEBMN8OoLLJxo4FkrwV")],
     "notes": "registry->fodhelper TEMPORAL/CONTEXTUAL; ancestry fodhelper->wscript->ps via parent.entity_id (verifier)"},
    {"stage": "S3", "host": "wmi", "account": "WMI\\Duc", "status": "PASS",
     "input_artifacts": ["ART-01-02"], "output_artifacts": [],
     "evidence_refs": [s3_write,
                       ref("AaEBMN8OoLLJxo4OlomC"), ref("AaEBMN8OoLLJxo4OlomI"),
                       ref("AaEBMN8OoLLJxo4Oloma")],
     "notes": "module integrity: guest svhw.ps1 sha256 == staged consumer raw (ART-01-02); binding refs 21.Consumer/Filter vs 19/20 Name cross-checked by verifier"},
    {"stage": "S4", "host": "wmi", "account": "NT AUTHORITY\\SYSTEM", "status": "PASS",
     "input_artifacts": [], "output_artifacts": [],
     "evidence_refs": [ref("AaEBMN8OoLLJxo6t5RwS"), ref("AaEBMN8OoLLJxo69_N8k")],
     "notes": "activation: console notepad trigger; consumer under WmiPrvSE as SYSTEM (parent entity = WmiPrvSE identity)"},
    {"stage": "S5", "host": "wmi", "account": "NT AUTHORITY\\SYSTEM", "status": "PASS",
     "input_artifacts": [], "output_artifacts": ["ART-06-01"],
     "evidence_refs": [ref("AaEBMN8OoLLJxo_OEQdW"), ref("AaEBMN8OoLLJxo_OEQdp"),
                       ref("AaEBMN8OoLLJxo_OEQeO")],
     "notes": "in-process queries (Get-CimInstance etc.) not independently evidenced; ARP.EXE parent entity == consumer entity (verifier)"},
    {"stage": "S6", "host": "wmi", "account": "NT AUTHORITY\\SYSTEM", "status": "PASS",
     "input_artifacts": ["ART-06-01"], "output_artifacts": ["ART-07-01"],
     "evidence_refs": [ref("AaEBMN8OoLLJxo_OFAgY"), ref("AaEBMN8OoLLJxo_OFAid"),
                       ref("AaEBMN8OoLLJxo_OFAju"), ref("AaEBMN8OoLLJxo_MDTG7"),
                       ref("AaEBMN8OoLLJxo_MDzFL"),
                       {"kind": "receipt", "artifact": "ART-07-01-*.json",
                        "detail": "sink receipt (server-side); raw sha256 + manifest canonical hash"}],
     "notes": "archive create (wdmp.zip) by consumer entity; curl E1/E3 entity-owned; PS status channel is NOT the transfer (S4 intent+connection; receipt proves transfer)"},
    {"stage": "S7", "host": "wmi", "account": "NT AUTHORITY\\SYSTEM", "status": "PASS",
     "input_artifacts": [], "output_artifacts": ["ART-08-01"],
     "evidence_refs": [ref("AaEBMN8OoLLJxo_bHnHx")],
     "notes": "wdmp.zip deletion; create/delete same file.path (verifier); Clear-Content history not event-evidenced"},
]

run_dir = ROOT / "evidence" / "runs" / RUN


def canon(p):
    return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest().upper()


def raw(p):
    return hashlib.sha256(p.read_bytes()).hexdigest().upper()


idx = []
for aid, rel, prod, cons in (
        ("ART-01-01", "payload/setup.bat", "S1", ""),
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
          "created_utc": "2026-10-03T09:54:40Z", "secrets_policy": "no-secrets-allowed",
          "stages": stages, "artifact_index": idx}
out = run_dir / f"{RUN}.json"
out.write_text(json.dumps(ledger, indent=2, ensure_ascii=False), encoding="utf-8")
print("wrote", out)
print("stages:", [(s["stage"], s["status"]) for s in stages])
print("artifacts:", [(a["artifact_id"], a["sha256"][:8]) for a in idx])
print("refs with entity:", sum(1 for s in stages for r in s["evidence_refs"] if r.get("entity_id")))
print("refs with file_path:", sum(1 for s in stages for r in s["evidence_refs"] if r.get("file_path")))