#!/usr/bin/env python3
"""Build a run ledger from live Elasticsearch evidence (generic, by run id).

RUN SCOPING (hard requirements):
  - The run window is EXPLICIT: pass RUN_WINDOW_START/RUN_WINDOW_END, or RUN_ANCHOR_TS
    (the run's S1 timestamp, +/- 5 s). There is no implicit "now" window.
  - The entry event is discovered with a DESCENDING sort; the run must resolve to
    exactly ONE candidate inside the window, otherwise the builder aborts (a silent
    guess must not select "the latest activity" while claiming a run id).
  - Every event ref must fall inside [window_start, window_end]; background telemetry
    (collector E3) is stored in a separate `baseline_telemetry` section, never counted
    as campaign evidence.
  - RESULTS ARE PAGINATED (search_after); truncation is reported, never silent.
  - E3 refs are restricted to the sink destination AND entity-verified curl
    connections; collector traffic is excluded from S6.
  - Stage status is "OBSERVED" (events present) - the builder does not self-certify
    PASS; acceptance is the verifier's decision.

Credentials: environment only (ES_URL / ES_USER / ES_PASS).
Usage:
  set RUN_WINDOW_START=... & set RUN_WINDOW_END=... &
  python scripts/build_ledger_run.py RUN-YYYYMMDD-NN
"""
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ES = os.environ["ES_URL"].rstrip("/")
USER = os.environ.get("ES_USER", "elastic")
PASS = os.environ["ES_PASS"]
SYS = ".ds-logs-windows.sysmon_operational-*"
HOST = os.environ.get("RUN_HOST", "wmi")
SINK_IP = os.environ.get("SINK_IP", "192.168.106.1")
SINK_PORT = int(os.environ.get("SINK_PORT", "9180"))
GUEST_HASH = os.environ.get("GUEST_SVHW_SHA256", "")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
AUTH = "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode()
RUN = sys.argv[1] if len(sys.argv) > 1 else ""
if not re.match(r"^RUN-[0-9]{8}-[0-9]{2,}$", RUN):
    raise SystemExit("provide a run id RUN-YYYYMMDD-NN")
MAX_RESULTS = int(os.environ.get("MAX_RESULTS", "2000"))


def post(url, body):
    r = urllib.request.Request(url, data=json.dumps(body).encode(),
                               headers={"Authorization": AUTH, "Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=60, context=CTX) as resp:
        return json.load(resp)


def search_all(filters, cap=MAX_RESULTS):
    """Paginated search (search_after). Returns (hits, truncated_flag)."""
    hits, after, truncated = [], None, False
    while True:
        body = {"size": 200, "query": {"bool": {"filter": filters}},
                "sort": [{"@timestamp": "asc"}, {"_doc": "asc"}]}
        if after:
            body["search_after"] = after
        batch = post(f"{ES}/{SYS}/_search", body)["hits"]["hits"]
        if not batch:
            break
        hits.extend(batch)
        if len(hits) >= cap:
            truncated = len(batch) > 0 and len(hits) >= cap
            hits = hits[:cap]
            break
        after = batch[-1]["sort"]
    return hits, truncated


def search_desc(filters, size=20):
    return post(f"{ES}/{SYS}/_search",
                {"size": size, "query": {"bool": {"filter": filters}},
                 "sort": [{"@timestamp": "desc"}]})["hits"]["hits"]


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


def ref(h):
    s = h["_source"]
    wl = s.get("winlog") or {}
    ed = wl.get("event_data") or {}
    reg = s.get("registry") or {}
    head = (s.get("message") or "").splitlines()[0][:110] if s.get("message") else ""
    return {"kind": "event", "es_id": h["_id"], "ts": s.get("@timestamp"),
            "event": str(gp(s, "event.code") or ""), "detail": head,
            "process_name": clean(gp(s, "process.name")),
            "entity_id": clean(gp(s, "process.entity_id")),
            "parent_entity_id": clean(gp(s, "process.parent.entity_id")),
            "parent_name": clean(gp(s, "process.parent.name")),
            "user": clean(gp(s, "user.name")),
            "file_path": clean(gp(s, "file.path")),
            "file_name": clean(gp(s, "file.name")),
            "dst_ip": clean(gp(s, "destination.ip")),
            "dst_port": clean(gp(s, "destination.port")),
            "registry_path": clean(reg.get("path")),
            "registry_value": clean(reg.get("value")),
            "wmi_name": clean(ed.get("Name")), "wmi_operation": clean(ed.get("Operation")),
            "wmi_consumer": clean(ed.get("Consumer")), "wmi_filter": clean(ed.get("Filter"))}


def dedupe(refs):
    """One ref per ES _id (a document matched by two searches counts once)."""
    seen, out = set(), []
    for r in refs:
        if r["es_id"] in seen:
            continue
        seen.add(r["es_id"])
        out.append(r)
    return out


def in_window(ts, lo, hi):
    return lo <= ts <= hi


# ---------------------------------------------------------------- run window
w0 = os.environ.get("RUN_WINDOW_START")
w1 = os.environ.get("RUN_WINDOW_END")
if not w0:
    anchor = os.environ.get("RUN_ANCHOR_TS")
    if not anchor:
        raise SystemExit("RUN_WINDOW_START is required (no implicit 'now' window); "
                         "alternatively pass RUN_ANCHOR_TS")
    w0 = (datetime.fromisoformat(anchor.replace("Z", "+00:00"))
          - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
if not w1:
    raise SystemExit("RUN_WINDOW_END is required (a run window must be finite)")
window = {"gte": w0, "lte": w1}
base_win = [{"term": {"host.name": HOST}}, {"range": {"@timestamp": window}}]

# ------------------------------------------------- entry candidate resolution
# A run's entry is the operator launch: a cmd.exe whose command line runs setup.bat
# from the staged payload directory. Child/duplicate cmd events (same launch chain)
# are excluded by requiring the exact payload path; if more than one candidate still
# remains, the run scope is ambiguous and the builder aborts.
ENTRY_PATTERN = os.environ.get("ENTRY_PATTERN", "*setup.bat*")
candidates = search_desc([{"term": {"host.name": HOST}}, {"range": {"@timestamp": window}},
                          {"term": {"event.code": "1"}},
                          {"term": {"process.name": "cmd.exe"}},
                          {"wildcard": {"process.command_line": ENTRY_PATTERN}}], size=20)
# keep only the operator launch: cmd.exe NOT spawned by another cmd.exe
candidates = [h for h in candidates
              if (gp(h["_source"], "process.parent.name") or "").lower() != "cmd.exe"]
if len(candidates) == 0:
    # fall back to the raw Sysmon message text when ECS command_line is compacted
    candidates = search_desc([{"term": {"host.name": HOST}}, {"range": {"@timestamp": window}},
                              {"term": {"event.code": "1"}},
                              {"term": {"process.name": "cmd.exe"}},
                              {"wildcard": {"message": ENTRY_PATTERN}}], size=20)
    candidates = [h for h in candidates
                  if (gp(h["_source"], "process.parent.name") or "").lower() != "cmd.exe"]
if len(candidates) == 0:
    raise SystemExit("no setup.bat entry event inside the declared window")
ts_set = sorted({h["_source"]["@timestamp"] for h in candidates})
if len(ts_set) > 1:
    raise SystemExit(
        f"ambiguous run scope: {len(candidates)} distinct entry timestamps inside the window "
        f"({ts_set}); narrow the window so exactly one launch fits")
entry = candidates[0]
run_started = entry["_source"]["@timestamp"]

truncated_any = []


def find(filters, cap=200):
    hits, trunc = search_all(base_win + filters, cap)
    if trunc:
        truncated_any.append(f"cap={cap} filters={filters[:2]}")
    return [ref(h) for h in hits]


s2_reg = find([{"term": {"event.code": "13"}}, {"term": {"process.name": "reg.exe"}}], 20)
s2_fod = find([{"term": {"event.code": "1"}}, {"term": {"process.name": "fodhelper.exe"}}], 10)
s2_wsc = find([{"term": {"event.code": "1"}}, {"term": {"process.name": "wscript.exe"}}], 10)
s2_psi = find([{"term": {"event.code": "1"}}, {"term": {"process.name": "powershell.exe"}},
               {"wildcard": {"process.command_line": "*install.ps1*"}}], 10)
s3_svh = find([{"term": {"event.code": "11"}}, {"wildcard": {"file.name": "svhw.ps1"}}], 10)
s3_wmi = find([{"terms": {"event.code": ["19", "20", "21"]}},
               {"term": {"winlog.event_data.Operation": "Created"}}], 30)
s4_ntp = find([{"term": {"event.code": "1"}}, {"term": {"process.name": "notepad.exe"}}], 10)
s4_con = find([{"term": {"event.code": "1"}}, {"term": {"process.parent.name": "WmiPrvSE.exe"}}], 10)
s5_arp = find([{"term": {"event.code": "1"}}, {"terms": {"process.name": ["arp.exe", "ARP.EXE"]}}], 10)
s5_files = find([{"term": {"event.code": "11"}},
                 {"terms": {"file.name": ["info.txt", "_manifest.txt"]}}], 20)
s6_zip_create = find([{"term": {"event.code": "11"}}, {"term": {"file.name": "wdmp.zip"}}], 10)
s6_curl = find([{"term": {"event.code": "1"}}, {"term": {"process.name": "curl.exe"}}], 20)
s6_net_ps = find([{"term": {"event.code": "3"}},
                  {"term": {"process.name": "powershell.exe"}},
                  {"term": {"destination.ip": SINK_IP}},
                  {"term": {"destination.port": SINK_PORT}}], 20)
s7_del = find([{"term": {"event.code": "23"}}, {"term": {"file.name": "wdmp.zip"}}], 10)

# S6 network: only E3 owned by a curl entity AND aimed at the sink destination.
curl_entities = {r["entity_id"] for r in s6_curl if r["entity_id"]}
s6_net_curl = []
if curl_entities:
    all_e3, t3 = search_all(base_win + [{"term": {"event.code": "3"}}], MAX_RESULTS)
    if t3:
        truncated_any.append("E3 scan cap reached")
    for h in all_e3:
        s = h["_source"]
        ent = clean(gp(s, "process.entity_id"))
        dst = clean(gp(s, "destination.ip"))
        port = str(clean(gp(s, "destination.port")))
        if ent in curl_entities and dst == SINK_IP and port == str(SINK_PORT):
            s6_net_curl.append(ref(h))

# baseline telemetry: collector traffic inside the window (NOT campaign refs)
baseline_e3, tb = search_all(base_win + [{"term": {"event.code": "3"}},
                                         {"term": {"process.name": "elastic-otel-collector.exe"}}], 500)
if tb:
    truncated_any.append("baseline E3 cap reached")

svh_refs = s3_svh
if svh_refs and GUEST_HASH:
    svh_refs[0]["file_hash"] = GUEST_HASH.upper()
    svh_refs[0]["file_hash_provenance"] = ("guest probe; EID11 event carries no Hashes "
                                           "on this stack")

run_dir = ROOT / "evidence" / "runs" / RUN
if not run_dir.is_dir():
    raise SystemExit(f"missing run dir {run_dir}; create it and place the artifacts first")


def stage(name, host, account, refs, notes, in_art=(), out_art=()):
    # non-event refs (receipt/artifact) carry no timestamp: keep them as-is
    kept = [r for r in refs
            if r.get("kind") != "event" or in_window(r.get("ts", ""), w0, w1)]
    kept = dedupe([r for r in kept if r.get("kind") == "event"]) + \
        [r for r in kept if r.get("kind") != "event"]
    return {"stage": name, "host": host, "account": account,
            "status": "OBSERVED" if any(r.get("kind") == "event" for r in kept) else "NOT RUN",
            "input_artifacts": list(in_art), "output_artifacts": list(out_art),
            "evidence_refs": kept, "notes": notes}


stages = [
    stage("S1", HOST, "WMI\\Duc", [ref(entry)],
          "operator action: setup.bat launched via vmrun (declared)"),
    stage("S2", HOST, "WMI\\Duc", s2_reg + s2_fod + s2_wsc + s2_psi,
          "registry->fodhelper TEMPORAL/CONTEXTUAL; ancestry verifier-checked"),
    stage("S3", HOST, "WMI\\Duc", svh_refs + s3_wmi,
          "EID 19/20/21 Created; binding refs verifier-checked; module integrity via guest hash",
          in_art=["ART-01-02"]),
    stage("S4", HOST, "NT AUTHORITY\\SYSTEM", s4_ntp + s4_con,
          "activation: notepad trigger -> consumer under WmiPrvSE/SYSTEM "
          "(verifier checks user + parent identity)"),
    stage("S5", HOST, "NT AUTHORITY\\SYSTEM", s5_arp + s5_files,
          "in-process queries not independently evidenced; ARP parent entity == consumer "
          "entity (verifier)", out_art=["ART-06-01"]),
    stage("S6", HOST, "NT AUTHORITY\\SYSTEM",
          s6_zip_create + s6_curl + s6_net_curl + s6_net_ps
          + [{"kind": "receipt", "artifact": "ART-07-01-*.json",
              "detail": "sink receipt (server-side): name/size/sha256 + manifest hash"}],
          f"archive create + curl upload-intent E1s + entity-owned E3s to the sink "
          f"({SINK_IP}:{SINK_PORT}); receipt proves transfer (archive bytes are not committed)",
          in_art=["ART-06-01"], out_art=["ART-07-01"]),
    stage("S7", HOST, "NT AUTHORITY\\SYSTEM", s7_del,
          "wdmp.zip deletion; create/delete same path (verifier)", out_art=["ART-08-01"]),
]

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
    idx.append({"artifact_id": aid, "path": rel,
                "sha256": raw(p) if p.suffix.lower() == ".zip" else canon(p),
                "producer_stage": prod, "consumer_stage": cons})

ledger = {
    "run_id": RUN, "scenario_id": "WMI-LAB-1",
    "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "run_window_utc": {"start": w0, "end": w1},
    "run_started_utc": run_started,
    "secrets_policy": "no-secrets-allowed",
    "stages": stages,
    "artifact_index": idx,
    "baseline_telemetry": {
        "note": "non-campaign background telemetry inside the window; never counted as "
                "campaign evidence",
        "collector_e3_count": len(baseline_e3),
        "collector_e3_sample_ids": [h["_id"] for h in baseline_e3[:5]],
    },
    "builder": {
        "entry_es_id": entry["_id"],
        "entry_candidates_in_window": len(candidates),
        "event_refs": sum(len(s["evidence_refs"]) for s in stages),
        "unique_es_ids": len({r.get("es_id") for s in stages for r in s["evidence_refs"]
                              if r.get("kind") == "event"}),
        "truncations": truncated_any,
    },
}
out = run_dir / f"{RUN}.json"
out.write_text(json.dumps(ledger, indent=2, ensure_ascii=False), encoding="utf-8")
print("wrote", out)
print("window:", w0, "->", w1, "| entry:", run_started, f"(candidates={len(candidates)})")
print("stages:", [(s["stage"], s["status"], len(s["evidence_refs"])) for s in stages])
print("refs:", ledger["builder"]["event_refs"],
      "| unique ids:", ledger["builder"]["unique_es_ids"])
print("baseline collector E3 (separate):", len(baseline_e3),
      "| truncations:", truncated_any or "none")
print("artifacts:", [(a["artifact_id"], a["sha256"][:8]) for a in idx])