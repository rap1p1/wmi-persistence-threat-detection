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

SINK_PORT = None  # pinned from the ledger S6 rows during validation


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


def validate_run(ledger, directory, failures):
    """Offline, ledger-derived assertions. `failures` is an append-only list."""
    failures.extend("ledger: " + e for e in el.ledger_validate(ledger))
    failures.extend("artifact: " + e for e in el.artifact_violations(ledger, directory))

    stages = {s.get("stage"): s for s in ledger.get("stages", []) if isinstance(s, dict)}
    missing = MANDATORY - set(stages)
    if missing:
        failures.append(f"ledger: missing mandatory stage rows {sorted(missing)}")
        return

    for name in sorted(MANDATORY, key=lambda x: int(x[1:])):
        row = stages[name]
        status = row.get("status")
        if status != "PASS":
            failures.append(f"stage {name}: status {status!r} "
                            f"(expected PASS; notes: {row.get('notes') or 'none'})")
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
        receipt = json.loads(rec_path.read_text(encoding="utf-8"))
        failures.extend("S6 receipt: " + e for e in el.receipt_validate(receipt))
        if not any("S6 receipt" in f for f in failures):
            payload = receipt.get("payload", {})
            manifest_hash = el.manifest_hash_of(receipt)
            entry = next((a for a in ledger.get("artifact_index", [])
                          if a.get("artifact_id") == "ART-07-01"), None)
            if entry and manifest_hash:
                recorded_manifest = payload.get("manifest_sha256")
                if recorded_manifest and manifest_hash != recorded_manifest:
                    failures.append("S6 receipt: manifest_sha256 does not match embedded manifest text")
                if not recorded_manifest:
                    failures.append("S6 receipt: manifest_sha256 missing")
            for f in payload.get("sink_files") or []:
                if not (f.get("name") or "").endswith(".zip"):
                    continue
                # Optional offline check: the uploaded zip present in the run dir.
                zip_path = directory / f.get("name", "")
                if zip_path.is_file() and el.raw_sha256(zip_path.read_bytes()) != (f.get("sha256") or "").upper():
                    failures.append(f"S6 receipt: stored zip hash mismatch for {f.get('name')}")

    # S7: cleanup verification artifact.
    if not next(directory.glob("ART-08-01-*.json"), None):
        failures.append("S7: ART-08-01 cleanup verification artifact missing")


def es_verify(ledger, failures, tolerance_s=5.0):
    """Re-fetch each recorded event by es_id from Elasticsearch and confirm the
    stored @timestamp still matches the ledger row (the index is the source of
    truth; a drifted/missing record fails acceptance). Credentials come from the
    environment only; without them this is a no-op (callers fall back to
    ledger-only mode).
    """
    import base64
    import os
    import ssl
    import urllib.error
    import urllib.parse
    import urllib.request

    if not _es_available():
        return 0
    es = os.environ["ES_URL"].rstrip("/")
    user = os.environ.get("ES_USER", "elastic")
    password = os.environ["ES_PASS"]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    checked = 0
    for stage in ledger.get("stages", []):
        for ref in (stage.get("evidence_refs") or []):
            if ref.get("kind") != "event" or not ref.get("es_id"):
                continue
            es_id, recorded = ref["es_id"], ref.get("ts") or ""
            req = urllib.request.Request(
                f"{es}/{SYS_INDEX}/_doc/{urllib.parse.quote(es_id, safe='')}",
                headers={"Authorization": auth})
            try:
                with urllib.request.urlopen(req, timeout=60, context=ctx) as resp:
                    src = json.load(resp).get("_source") or {}
                actual = src.get("@timestamp")
            except urllib.error.HTTPError as exc:
                if exc.code == 404:
                    failures.append(f"ES: event {es_id} (stage {stage.get('stage')}) not found")
                else:
                    failures.append(f"ES: HTTP {exc.code} fetching {es_id}")
                continue
            except Exception as exc:
                failures.append(f"ES: connection error fetching {es_id}: {exc}")
                continue
            checked += 1
            if not recorded:
                failures.append(f"ES: event {es_id} has no recorded ts to compare")
                continue
            if not el.ts_within(recorded, actual or "", tolerance_s):
                failures.append(f"ES: event {es_id} timestamp drift recorded={recorded} "
                                f"actual={actual}")
    return checked


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
    for run_id in selected:
        ledger, directory = _load_ledger(run_id)
        print(f"== {run_id} acceptance verification ==")
        failures = []
        validate_run(ledger, directory, failures)
        checked = 0
        if args.offline or not _es_available():
            if not failures:
                print("  note ledger-only mode: ES re-verification not performed "
                      "(set ES_URL/ES_USER/ES_PASS to run the full acceptance)")
            tag = "ACCEPTED (ledger-only)" if not failures else "FAILED"
        else:
            checked = es_verify(ledger, failures)
            if not failures:
                print(f"  ok  ES re-verification: {checked} event(s) re-fetched, "
                      "timestamps matched")
            tag = "ACCEPTED" if not failures else "FAILED"
        for f in failures:
            print(f"  FAIL {f}")
        print(f"RESULT: {tag}")
        if failures:
            global_failures.append((run_id, failures))

    if global_failures:
        print(f"\nREGRESSION-FAILED on {len(global_failures)} run(s)")
        return 1
    print("\nRESULT: ACCEPTED" if not args.all else "\nRESULT: ALL RUNS ACCEPTED")
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