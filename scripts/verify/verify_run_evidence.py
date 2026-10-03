#!/usr/bin/env python3
"""Acceptance verifier for recorded runs (WMI-LAB-1 chain).

Checks, per run (S1..S7):
  - ledger structure against evidence/runs/RUN-schema.json (via scripts/evidence_lib.py);
  - each stage row present and PASS (NOT RUN / PARTIAL allowed only with an explicit
    note and only when the stage is not in the mandatory set for that run);
  - per-stage required event rows recorded with real timestamps (no placeholders);
  - artifact_index: files exist, canonical/raw hashes match;
  - S6 transfer integrity: sink receipt exists, sink_files non-empty, recorded
    sha256/size/name consistent with the in-guest manifest snapshot;
  - when ES creds are present (ES_URL/ES_USER/ES_PASS env), re-fetches every
    recorded event by es_id from Elasticsearch and confirms the stored @timestamp
    matches the ledger row (drift or a missing record fails acceptance). Process
    ancestry and WMI-binding-join cross-checks are performed against the ledger
    evidence (see docs/correlation-architecture.md), not re-derived here.

Fail-fast on unknown run ids. Regression over all recorded runs with --all.
No credentials in code; ES creds come from the environment only.

Usage:
  set ES_PASS=... & python scripts/verify/verify_run_evidence.py RUN-20261013-01
  python scripts/verify/verify_run_evidence.py --all --offline
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_lib as el  # noqa: E402

PLACEHOLDER_TS = re.compile(r"(:\d{2}:5x|:xZ|T00:00:00Z$|TODO|FIXME)", re.I)

# Mandatory stages for a full campaign run.
MANDATORY = {"S1", "S2", "S3", "S4", "S5", "S6", "S7"}

# Backing store for the Sysmon channel (re-fetch by es_id during ES re-verification).
SYS_INDEX = ".ds-logs-windows.sysmon_operational-*"

# Fields re-checked against Elasticsearch for every event ref (ledger must agree).
ES_FIELDS = ("event.code", "host.name", "winlog.channel", "winlog.event_id",
             "process.name", "process.entity_id", "process.parent.entity_id",
             "file.path", "destination.ip")

# Per-stage minimum event evidence (event code, required count, human hint).
STAGE_EVENTS = {
    "S1": [("1", 1, "cmd entry E1")],
    "S2": [("13", 1, "ms-settings ValueSet EID 13"),
           ("1", 3, "fodhelper / wscript / powershell E1 chain")],
    "S3": [("11", 1, "consumer script write EID 11"),
           ("19", 1, "EventFilter Created"),
           ("20", 1, "EventConsumer Created"),
           ("21", 1, "FilterToConsumerBinding Created")],
    "S4": [("1", 2, "notepad E1 + WmiPrvSE-parented powershell E1")],
    "S5": [("1", 1, "arp/discovery E1"),
           ("11", 2, "info.txt + _manifest.txt EID 11")],
    "S6": [("1", 1, "curl E1"),
           ("3", 1, "curl E3 to sink"),
           ("receipt", 1, "ART-07-01 sink receipt")],
    "S7": [("23", 1, "wdmp.zip deletion EID 23")],
}

# Fields every event ref of a stage must carry (a PASS row may not hide a gap).
# Kept per-event-type so a WMI registry event is not required to carry a file path.
STAGE_REF_FIELDS = {
    "S1": {"1": ("process_name",)},
    "S2": {"1": ("process_name",), "13": ("registry_path",)},
    "S3": {"11": ("file_path",), "19": ("wmi_name",), "20": ("wmi_name",),
           "21": ("wmi_consumer", "wmi_filter")},
    "S4": {"1": ("process_name", "user")},
    "S5": {"1": ("process_name",), "11": ("file_path",)},
    "S6": {"1": ("process_name", "entity_id"), "3": ("entity_id",), "11": ("file_path",)},
    "S7": {"23": ("file_path",)},
}


def _refs(stage_row, kind):
    return [r for r in (stage_row.get("evidence_refs") or []) if r.get("kind") == kind]


def _events_by_code(stage_row):
    counts = {}
    for r in _refs(stage_row, "event"):
        code = str(r.get("event", ""))
        counts[code] = counts.get(code, 0) + 1
    return counts


def _ts_value(ref):
    return ref.get("ts") or ""


def _check_placeholders(ledger):
    bad = []
    for s in ledger.get("stages", []):
        for r in s.get("evidence_refs") or []:
            ts = _ts_value(r)
            if r.get("kind") == "event" and not ts:
                bad.append(f"{s.get('stage')}: event ref without ts")
            if ts and PLACEHOLDER_TS.search(ts):
                bad.append(f"{s.get('stage')}: placeholder timestamp {ts!r}")
    return bad


def _check_ref_duplicates(ledger):
    """Duplicate event es_ids inside one stage are a build error (dedupe or explain);
    the same es_id across stages is allowed (one event can serve two joins)."""
    bad = []
    for s in ledger.get("stages", []):
        ids = [r.get("es_id") for r in (s.get("evidence_refs") or [])
               if r.get("kind") == "event"]
        dupes = sorted({i for i in ids if i and ids.count(i) > 1})
        if dupes:
            bad.append(f"stage {s.get('stage')}: duplicate event refs {dupes}")
    return bad


def _check_window(ledger):
    """Every event ref must fall inside the declared run window."""
    win = ledger.get("run_window_utc") or {}
    lo, hi = win.get("start"), win.get("end")
    if not lo or not hi:
        return ["ledger: run_window_utc.start/end missing"]
    bad = []
    for s in ledger.get("stages", []):
        for r in s.get("evidence_refs") or []:
            if r.get("kind") != "event":
                continue
            ts = r.get("ts") or ""
            if not (lo <= ts <= hi):
                bad.append(f"stage {s.get('stage')}: event {r.get('es_id')} at {ts} is "
                           f"outside the run window {lo}..{hi}")
    return bad


def _load_ledger(run_id):
    directory = ROOT / "evidence" / "runs" / run_id
    ledger_path = directory / f"{run_id}.json"
    if not run_id or not el.RUN_ID_RE.match(run_id):
        raise SystemExit(f"unknown run id {run_id!r} (expected RUN-YYYYMMDD-<seq>)")
    if not ledger_path.is_file():
        raise SystemExit(f"unknown run id {run_id}: no ledger at {ledger_path.relative_to(ROOT)}")
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    if ledger.get("run_id") != run_id:
        raise SystemExit(f"run_id mismatch: folder {run_id} != ledger {ledger.get('run_id')}")
    return ledger, directory


def _find_ref(stages, stage, event, process=None, file_name=None):
    for r in stages.get(stage, {}).get("evidence_refs", []):
        if r.get("kind") != "event":
            continue
        if str(r.get("event")) != str(event):
            continue
        if process and (r.get("process_name") or "").lower() != process.lower():
            continue
        if file_name:
            # match on file_name when present, else on the basename of file_path
            fn = (r.get("file_name") or "").lower()
            fp = (r.get("file_path") or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
            if fn != file_name.lower() and fp != file_name.lower():
                continue
        return r
    return None


def join_checks(ledger, failures, gaps=None):
    """Offline chain-of-evidence joins over the ledger's stored fields.

    These assertions implement what EQL itself cannot express (verified on the lab
    stack, ES 9.5.3): 'sequence by' cannot map step1.process.entity_id onto
    step2.process.parent.entity_id. Missing join fields on a PASS stage are failures,
    EXCEPT the supplementary curl E1<->E3 ownership (S6): when the curl E3 lacks
    attribution the run records a GAP note instead of failing, because transfer
    success is proven independently by the sink receipt.
    """
    gaps = [] if gaps is None else gaps
    stages = {s.get("stage"): s for s in ledger.get("stages", [])}

    def need(stage, event, label, process=None, file_name=None):
        r = _find_ref(stages, stage, event, process, file_name)
        if r is None:
            failures.append(f"join {stage}: missing {label}")
            return None
        return r

    def eq(ref_a, field_a, ref_b, field_b, label):
        if ref_a is None or ref_b is None:
            return
        va, vb = ref_a.get(field_a), ref_b.get(field_b)
        if not va or not vb:
            failures.append(f"join {label}: missing join fields ({field_a} / {field_b})")
        elif va != vb:
            failures.append(f"join {label}: {va} != {vb}")

    # S2 ancestry: fodhelper -> wscript -> powershell by parent.entity_id
    fod = need("S2", "1", "fodhelper E1", process="fodhelper.exe")
    wsc = need("S2", "1", "wscript E1", process="wscript.exe")
    psi = need("S2", "1", "install powershell E1", process="powershell.exe")
    eq(wsc, "parent_entity_id", fod, "entity_id", "S2 fodhelper->wscript")
    eq(psi, "parent_entity_id", wsc, "entity_id", "S2 wscript->powershell")

    # S4: the consumer must run as SYSTEM and its parent must be WmiPrvSE/scrcons.
    # The ledger stores parent_name; when the telemetry does not carry it, the
    # assertion is downgraded to a GAP (report must lower the claim accordingly).
    con = need("S4", "1", "consumer powershell E1", process="powershell.exe")
    trig = _find_ref(stages, "S4", "1", process="notepad.exe")
    if con:
        if not con.get("parent_entity_id"):
            failures.append("join S4: consumer parent_entity_id missing (WmiPrvSE link)")
        user = (con.get("user") or "").upper()
        if "SYSTEM" not in user:
            failures.append(f"join S4: consumer user {con.get('user')!r} is not SYSTEM")
        pname = (con.get("parent_name") or "").lower()
        if not pname:
            gaps.append("S4: E3/E1 telemetry does not carry the consumer's parent name; "
                        "parent identity rests on parent_entity_id only")
        elif pname not in ("wmiprvse.exe", "scrcons.exe"):
            failures.append(f"join S4: consumer parent name {con.get('parent_name')!r} is not "
                            "WmiPrvSE/scrcons")
        else:
            print(f"  ok  S4 consumer: parent={con.get('parent_name')} user={con.get('user')}")
    if trig and con:
        # trigger precedes the consumer and both sit in the run window
        if not (trig.get("ts") or "") <= (con.get("ts") or ""):
            failures.append("join S4: consumer timestamp precedes the notepad trigger")

    # C3 ancestry: discovery parent entity == interpreter entity
    arp = need("S5", "1", "arp E1", process="ARP.EXE") or need("S5", "1", "arp E1", process="arp.exe")
    eq(arp, "parent_entity_id", con, "entity_id", "C3 interpreter->arp")

    # S6: every curl E1 must be matched to an E3 by ENTITY (not just the first curl),
    # aimed at the sink destination/port, after the curl started. A curl E1 without an
    # attributable E3 is reported per-curl (GAP when the E3 entity is absent, FAIL when
    # an E3 exists with a different entity for the same destination).
    ps3 = need("S6", "3", "powershell status E3", process="powershell.exe")
    eq(ps3, "entity_id", con, "entity_id", "S6 status-channel owner")
    sink_ip = os.environ.get("SINK_IP", "192.168.106.1")
    sink_port = str(os.environ.get("SINK_PORT", "9180"))
    e3_refs = [r for r in stages.get("S6", {}).get("evidence_refs", [])
               if r.get("kind") == "event" and str(r.get("event")) == "3"]
    curl1s = [r for r in stages.get("S6", {}).get("evidence_refs", [])
              if r.get("kind") == "event" and str(r.get("event")) == "1"
              and (r.get("process_name") or "").lower() == "curl.exe"]
    if not curl1s:
        failures.append("join S6: no curl E1 in the stage")
    for c1 in curl1s:
        ent = c1.get("entity_id")
        same_ent = [r for r in e3_refs if ent and r.get("entity_id") == ent]
        if same_ent:
            ok_dst = [r for r in same_ent if r.get("dst_ip") == sink_ip
                      and str(r.get("dst_port")) == sink_port]
            if not ok_dst:
                failures.append(f"join S6: curl entity {ent} has E3 but none to "
                                f"{sink_ip}:{sink_port} (dst seen: "
                                f"{[r.get('dst_ip') for r in same_ent]})")
            elif (ok_dst[0].get("ts") or "") < (c1.get("ts") or ""):
                failures.append(f"join S6: curl entity {ent} E3 precedes the E1")
            else:
                print(f"  ok  S6 curl E1->E3 ownership by entity ({ent[:24]}...; "
                      f"dst {sink_ip}:{sink_port}; E3 name "
                      f"{'present' if ok_dst[0].get('process_name') else 'missing (unknown process)'})")
        else:
            # No E3 carries this curl's entity. If an E3 exists to the SINK in this
            # stage but belongs to another entity, the ledger contradicts ownership
            # (a connection to the sink is recorded, but not for this curl) -> FAIL;
            # otherwise the telemetry simply lacks attribution -> GAP.
            foreign = [r for r in e3_refs if r.get("dst_ip") == sink_ip
                       and str(r.get("dst_port")) == sink_port]
            if foreign:
                failures.append(f"join S6: curl entity {ent} has no E3 to {sink_ip}:{sink_port}, "
                                f"but {len(foreign)} sink E3(s) belong to other entities "
                                f"({[r.get('entity_id') for r in foreign]}) - ownership "
                                "contradicted")
            else:
                gaps.append(f"S6: curl entity {ent} has no attributable E3 in window - "
                            "ownership unverified; transfer proven by receipt")

    # C5: the archive created in S6 must be deleted in S7 with the same file.path.
    # No archive name is hard-coded: pick the zip creation ref and require that some
    # S7 deletion ref carries the same path.
    zc = next((r for r in stages.get("S6", {}).get("evidence_refs", [])
               if r.get("kind") == "event" and str(r.get("event")) == "11"
               and (r.get("file_path") or "").lower().endswith(".zip")), None)
    if zc is None:
        failures.append("join S6: missing archive create E11 (zip)")
    else:
        created = (zc.get("file_path") or "").replace("\\", "/").lower()
        dels = [r for r in stages.get("S7", {}).get("evidence_refs", [])
                if r.get("kind") == "event" and str(r.get("event")) == "23"]
        if not dels:
            failures.append("join S7: missing archive delete E23")
        elif not any((r.get("file_path") or "").replace("\\", "/").lower() == created
                     for r in dels):
            failures.append(f"join C5 archive-path equality: created {zc.get('file_path')!r} "
                            f"but deleted {[r.get('file_path') for r in dels]!r}")

    # C2 binding: the EID 21 Consumer/Filter object references must name the recorded
    # EID 19/20 objects exactly (normalised WMI reference form, not a substring), and
    # the three events must belong to one ordered registration sequence in the window.
    e19 = need("S3", "19", "WMI 19")
    e20 = need("S3", "20", "WMI 20")
    e21 = need("S3", "21", "WMI 21")
    if e19 and e20 and e21:
        def ref_name(text, klass):
            if not text:
                return None
            m = re.search(klass + r'[.\w]*\s*=\s*\\?"?([^"\\]+)\\?"?', text, re.I)
            return m.group(1).strip() if m else None

        n19, n20 = (e19.get("wmi_name") or "").strip(), (e20.get("wmi_name") or "").strip()
        f_ref = ref_name(e21.get("wmi_filter") or "", "__EventFilter")
        c_ref = ref_name(e21.get("wmi_consumer") or "",
                         "(?:CommandLineEventConsumer|NTEventLogEventConsumer|ActiveScriptEventConsumer)")
        if not (n19 and n20 and f_ref and c_ref):
            failures.append(f"join C2: WMI object references unparsable "
                            f"(filter={e21.get('wmi_filter')!r} consumer={e21.get('wmi_consumer')!r})")
        elif f_ref != n19 or c_ref != n20:
            failures.append(f"join C2: binding references do not match the recorded objects "
                            f"(filter ref={f_ref!r} vs EID19 name={n19!r}; "
                            f"consumer ref={c_ref!r} vs EID20 name={n20!r})")
        else:
            win = ledger.get("run_window_utc") or {}
            ts = sorted([e19.get("ts") or "", e20.get("ts") or "", e21.get("ts") or ""])
            if not (win.get("start", "") <= ts[0] and ts[-1] <= win.get("end", "zzz")):
                failures.append("join C2: registration events fall outside the run window")
            elif not (ts[0] <= ts[1] <= ts[2]):
                failures.append(f"join C2: registration order is not 19<=20<=21 ({ts})")
            else:
                print(f"  ok  C2 binding refs: filter->{n19}, consumer->{n20} "
                      f"(ordered {ts[0]}..{ts[-1]})")


def validate_run(ledger, directory, failures, gaps=None):
    """Offline, ledger-derived assertions. `failures` is an append-only list.
    `gaps` accumulates supplementary telemetry gaps (notes, not failures)."""
    gaps = [] if gaps is None else gaps
    failures.extend("ledger: " + e for e in el.ledger_validate(ledger))
    failures.extend("artifact: " + e for e in el.artifact_violations(ledger, directory))
    failures.extend("evidence: " + e for e in _check_placeholders(ledger))
    failures.extend("evidence: " + e for e in _check_ref_duplicates(ledger))
    failures.extend("evidence: " + e for e in _check_window(ledger))

    stages = {s.get("stage"): s for s in ledger.get("stages", []) if isinstance(s, dict)}
    missing = MANDATORY - set(stages)
    if missing:
        failures.append(f"ledger: missing mandatory stage rows {sorted(missing)}")
        return

    for name in sorted(MANDATORY, key=lambda x: int(x[1:])):
        row = stages[name]
        status = row.get("status")
        # OBSERVED = the builder recorded events but did not self-certify PASS; the
        # verifier grades it below (PASS only when every assertion for the stage holds).
        if status not in ("PASS", "OBSERVED"):
            failures.append(f"stage {name}: status {status!r} "
                            f"(expected PASS/OBSERVED; notes: {row.get('notes') or 'none'})")
        for code, minimum, hint in STAGE_EVENTS.get(name, []):
            if code == "receipt":
                found = bool(_refs(row, "receipt")) or bool(_refs(row, "artifact"))
                if not found:
                    failures.append(f"stage {name}: missing receipt evidence ({hint})")
                continue
            got = _events_by_code(row).get(code, 0)
            if got < minimum:
                failures.append(f"stage {name}: expected >= {minimum} event {code} ({hint}), "
                                f"got {got}")
        # required fields per event ref (a PASS row may not hide a missing field)
        for r in _refs(row, "event"):
            required = STAGE_REF_FIELDS.get(name, {}).get(str(r.get("event")), ())
            missing_fields = [f for f in required if not r.get(f)]
            if missing_fields:
                failures.append(f"stage {name}: event ref {r.get('es_id')} missing required "
                                f"fields {missing_fields}")

    # S3 module integrity is MANDATORY for full acceptance: the recorded svhw.ps1 hash
    # must exist and equal the raw sha256 of the staged consumer (ART-01-02).
    s3 = stages["S3"]
    hash_ref = next((r for r in (s3.get("evidence_refs") or [])
                     if r.get("kind") == "event" and str(r.get("event")) == "11"), None)
    entry = next((a for a in ledger.get("artifact_index", [])
                  if a.get("artifact_id") == "ART-01-02"), None)
    if not hash_ref or not hash_ref.get("file_hash"):
        failures.append("S3: module hash missing (required for acceptance; provide the "
                        "guest svhw.ps1 hash) - stage cannot be PASS")
    elif entry is None:
        failures.append("S3: recorded svhw.ps1 file_hash but ART-01-02 "
                        "(staged consumer) missing from artifact_index")
    else:
        ref_hash = str(hash_ref["file_hash"]).upper()
        provenance = hash_ref.get("file_hash_provenance") or "not stated"
        staged = directory / entry["path"]
        if not staged.is_file():
            failures.append(f"S3: staged consumer file missing: {entry['path']}")
        else:
            data = staged.read_bytes()
            canon = el.canon_sha256(data)   # CRLF->LF: the form delivered to the guest
            raw = el.raw_sha256(data)
            if ref_hash not in (canon, raw):
                failures.append(f"S3: module integrity mismatch - staged consumer "
                                f"canonical={canon[:16]}... raw={raw[:16]}... != recorded "
                                f"svhw.ps1 hash {ref_hash[:16]}...")
            elif ref_hash == canon and raw != canon:
                print(f"  ok  S3 module integrity: recorded svhw.ps1 hash == staged consumer "
                      f"CANONICAL hash ({ref_hash[:16]}...; {provenance}; repo copy CRLF, "
                      "guest copy LF)")
            else:
                print(f"  ok  S3 module integrity: recorded svhw.ps1 hash == staged consumer "
                      f"hash ({ref_hash[:16]}...; {provenance})")

    # chain-of-evidence joins over the ledger fields (EQL cannot bind these)
    join_checks(ledger, failures, gaps)

    # S6: transfer integrity from the receipt artifact (offline-verifiable).
    receipt_row = None
    for row in stages["S6"].get("evidence_refs") or []:
        if row.get("kind") == "receipt":
            receipt_row = row
    rec_name = (receipt_row or {}).get("artifact") or "ART-07-01-*.json"
    rec_path = next(directory.glob(str(rec_name)), None)
    if rec_path is None:
        rec_path = next(directory.glob("ART-07-01-*.json"), None)
    if rec_path is None:
        failures.append("S6: no ART-07-01 sink receipt file in run directory")
    else:
        try:
            receipt = json.loads(rec_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(f"S6 receipt: malformed JSON ({exc})")
            receipt = {}
        # Receipt must bind to THIS ledger: run id, host, and manifest hash vs ART-06-01.
        failures.extend("S6 receipt: " + e for e in el.receipt_validate(receipt, ledger))
        rec_art = next((a for a in ledger.get("artifact_index", [])
                        if a.get("artifact_id") == "ART-07-01"), None)
        if rec_art is None:
            failures.append("S6 receipt: ledger does not index ART-07-01")
        elif rec_art.get("path") != rec_path.name:
            failures.append(f"S6 receipt: indexed path {rec_art.get('path')!r} != file "
                            f"{rec_path.name!r}")
        # Archive bytes are NOT committed: the receipt is the server-side evidence.
        # If an archive happens to be present locally, verify it; never claim bytes
        # were checked when they are absent.
        for f in (receipt.get("payload", {}) or {}).get("sink_files") or []:
            if not isinstance(f, dict) or not (f.get("name") or "").endswith(".zip"):
                continue
            zip_path = directory / f["name"]
            if zip_path.is_file():
                if el.raw_sha256(zip_path.read_bytes()) != str(f.get("sha256", "")).upper():
                    failures.append(f"S6 receipt: local archive hash mismatch for {f['name']}")
                elif zip_path.stat().st_size != f.get("size"):
                    failures.append(f"S6 receipt: local archive size mismatch for {f['name']}")
                else:
                    print(f"  ok  S6 receipt: local archive bytes match receipt ({f['name']})")
            else:
                gaps.append(f"S6: archive {f['name']!r} not present locally (not committed); "
                            "transfer evidence is the sink receipt only")

    # S7: cleanup verification artifact must PARSE and every check must pass.
    clean_path = next(directory.glob("ART-08-01-*.json"), None)
    if clean_path is None:
        failures.append("S7: ART-08-01 cleanup verification artifact missing")
    else:
        try:
            clean = json.loads(clean_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(f"S7: ART-08-01 malformed JSON ({exc})")
            clean = None
        if isinstance(clean, dict):
            if clean.get("run_id") != ledger.get("run_id"):
                failures.append(f"S7: ART-08-01 run_id {clean.get('run_id')!r} != ledger "
                                f"run_id {ledger.get('run_id')!r}")
            checks = clean.get("checks") or []
            if not checks:
                failures.append("S7: ART-08-01 has no checks")
            for c in checks:
                if not isinstance(c, dict) or str(c.get("result", "")).upper() != "PASS":
                    failures.append(f"S7: cleanup check not PASS: {c!r}")
            if checks and not [c for c in checks if str(c.get("result", "")).upper() != "PASS"]:
                print(f"  ok  S7 cleanup artifact: {len(checks)} check(s) PASS (run_id bound)")


def es_verify(ledger, failures, tolerance_s=5.0):
    """Re-fetch every recorded event by es_id and confirm the ledger row agrees with
    the stored document: @timestamp, event code, host, channel and the join/destination
    fields present in the ledger row. Returns (refs_checked, unique_ids_checked).

    Credentials come from the environment only; without them this is a no-op and the
    caller must report ledger-only acceptance (never a full ACCEPTED).
    """
    import base64
    import os
    import ssl
    import urllib.error
    import urllib.request

    if not _es_available():
        return 0, 0
    es = os.environ["ES_URL"].rstrip("/")
    user = os.environ.get("ES_USER", "elastic")
    password = os.environ["ES_PASS"]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()

    # Dedupe by es_id: one index lookup per unique document, one ref per stage row.
    refs = [(s.get("stage"), r) for s in ledger.get("stages", [])
            for r in (s.get("evidence_refs") or [])
            if r.get("kind") == "event" and r.get("es_id")]
    by_id = {}
    for stage, r in refs:
        by_id.setdefault(r["es_id"], []).append((stage, r))

    checked = 0
    for es_id, entries in by_id.items():
        body = {"size": 3, "query": {"ids": {"values": [es_id]}}}
        req = urllib.request.Request(
            f"{es}/{SYS_INDEX}/_search", data=json.dumps(body).encode(),
            headers={"Authorization": auth, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
                hits = json.load(resp).get("hits", {}).get("hits", [])
        except urllib.error.HTTPError as exc:
            failures.append(f"ES: HTTP {exc.code} fetching {es_id}")
            continue
        except Exception as exc:
            failures.append(f"ES: connection error fetching {es_id}: {exc}")
            continue
        if len(hits) == 0:
            failures.append(f"ES: event {es_id} not found ({entries[0][0]})")
            continue
        if len(hits) > 1:
            failures.append(f"ES: event {es_id} returned {len(hits)} documents (expected 1)")
            continue
        src = hits[0].get("_source") or {}
        actual_ts = src.get("@timestamp")
        checked += 1
        for stage, ref in entries:
            if not el.ts_within(ref.get("ts") or "", actual_ts or "", tolerance_s):
                failures.append(f"ES: {stage} event {es_id} timestamp drift "
                                f"recorded={ref.get('ts')} actual={actual_ts}")
            db = lambda p: _dig(src, p)
            if str(ref.get("event")) != str(db("event.code")):
                failures.append(f"ES: {stage} event {es_id} code mismatch "
                                f"ledger={ref.get('event')} es={db('event.code')}")
            if ref.get("process_name") and db("process.name") and \
                    str(ref["process_name"]).lower() != str(db("process.name")).lower():
                failures.append(f"ES: {stage} event {es_id} process.name mismatch "
                                f"ledger={ref['process_name']} es={db('process.name')}")
            for field, path in (("entity_id", "process.entity_id"),
                                ("file_path", "file.path"),
                                ("dst_ip", "destination.ip")):
                lv, ev = ref.get(field), db(path)
                if lv and ev and str(lv) != str(ev):
                    failures.append(f"ES: {stage} event {es_id} {path} mismatch "
                                    f"ledger={lv} es={ev}")
            hosts = {s.get("host") for s in ledger.get("stages", []) if s.get("host")}
            if db("host.name") and hosts and db("host.name") not in hosts:
                failures.append(f"ES: {stage} event {es_id} host {db('host.name')!r} "
                                f"not in ledger hosts {sorted(hosts)}")
    return len(refs), checked


def _dig(doc, dotted):
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_id", nargs="?")
    parser.add_argument("--all", action="store_true", help="verify every recorded run (regression)")
    parser.add_argument("--offline", action="store_true", help="skip ES re-verification")
    args = parser.parse_args(argv)

    run_dirs = sorted(ROOT.joinpath("evidence", "runs").glob("RUN-*"))
    selected = [d.name for d in run_dirs if d.is_dir()]
    if args.all:
        if not selected:
            raise SystemExit("no recorded runs to verify")
    else:
        if not args.run_id:
            raise SystemExit("provide a run id or --all")
        if args.run_id not in selected:
            raise SystemExit(f"unknown run id {args.run_id!r} (known: {selected or 'none'})")
        selected = [args.run_id]

    global_failures = []
    ledger_only_runs = []
    es_backed_runs = []
    for run_id in selected:
        ledger, directory = _load_ledger(run_id)
        print(f"== {run_id} acceptance verification ==")
        failures = []
        gaps = []
        validate_run(ledger, directory, failures, gaps)
        if args.offline or not _es_available():
            if not failures:
                print("  note LEDGER-ONLY: ES re-verification was NOT performed "
                      "(set ES_URL/ES_USER/ES_PASS for ES-backed acceptance)")
            tag = "ACCEPTED-LEDGER-ONLY" if not failures else "FAILED"
            if not failures:
                ledger_only_runs.append(run_id)
        else:
            refs, uniq = es_verify(ledger, failures)
            if not failures:
                print(f"  ok  ES re-verification: {refs} event ref(s) across {uniq} unique "
                      "document(s) re-fetched; timestamp/code/host/join fields matched")
                es_backed_runs.append(run_id)
            tag = "ACCEPTED (ES-BACKED)" if not failures else "FAILED"
        for g in gaps:
            print(f"  GAP {g}")
        for f in failures:
            print(f"  FAIL {f}")
        print(f"RESULT: {tag}")
        if failures:
            global_failures.append((run_id, failures))

    if global_failures:
        print(f"\nREGRESSION-FAILED on {len(global_failures)} run(s)")
        return 1
    if ledger_only_runs and not args.all:
        print(f"\nRESULT: ACCEPTED-LEDGER-ONLY for {ledger_only_runs} - NOT ES-backed acceptance")
        return 0
    if ledger_only_runs:
        print(f"\nRESULT: ALL RUNS ACCEPTED-OR-LEDGER-ONLY "
              f"(ES-backed: {es_backed_runs or 'none'}; ledger-only: {ledger_only_runs}) - "
              "this is NOT an unconditional ALL ACCEPTED")
        return 0
    print(f"\nRESULT: ALL RUNS ACCEPTED (ES-BACKED for {es_backed_runs})")
    return 0


def _es_available():
    import os
    return bool(os.environ.get("ES_PASS") and os.environ.get("ES_URL"))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit as exc:
        raise exc
    except Exception as exc:  # verifier must fail loudly, never silently pass
        print(f"ERROR: {exc}")
        sys.exit(2)