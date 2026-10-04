#!/usr/bin/env python3
"""Capture run provenance into the ledger (checked-in evidence, no secrets).

Records what can be observed: repo commit, hashes of the telemetry config and the
live rule export, observed versions from the stack (ES/Sysmon/Agent where available),
run window, and the sink receipt identity. Fields that cannot be established are
written as "not captured" - never guessed.

Usage: python scripts/capture_provenance.py RUN-YYYYMMDD-NN
"""
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import base64
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUN = sys.argv[1] if len(sys.argv) > 1 else ""
if not re.match(r"^RUN-[0-9]{8}-[0-9]{2,}$", RUN):
    raise SystemExit("provide a run id")

run_dir = ROOT / "evidence" / "runs" / RUN
ledger_path = run_dir / f"{RUN}.json"
if not ledger_path.is_file():
    raise SystemExit(f"no ledger at {ledger_path}")


def sha256_file(p):
    return hashlib.sha256(p.read_bytes()).hexdigest().upper() if p.is_file() else "not captured"


def git(*args):
    try:
        return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True,
                              timeout=20).stdout.strip() or "not captured"
    except Exception:
        return "not captured"


def git_diff_sha256():
    """Hash of the uncommitted diff at capture time (working tree vs HEAD). When the
    tree is dirty this pins the delta, so the recorded commit plus this hash identify
    the actual source state that ran; without it, the commit alone could not
    reproduce the run's files."""
    try:
        r = subprocess.run(["git", "diff", "HEAD"], cwd=ROOT, capture_output=True,
                           text=True, timeout=20)
        if r.returncode != 0:
            return "not captured (git diff failed)"
        return hashlib.sha256(r.stdout.encode("utf-8", "replace")).hexdigest().upper()
    except Exception:
        return "not captured"


def es_version():
    url = os.environ.get("ES_URL")
    pw = os.environ.get("ES_PASS")
    if not (url and pw):
        return "not captured (no ES credentials in this environment)"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    auth = "Basic " + base64.b64encode(
        f"{os.environ.get('ES_USER','elastic')}:{pw}".encode()).decode()
    try:
        r = urllib.request.Request(url.rstrip("/") + "/", headers={"Authorization": auth})
        with urllib.request.urlopen(r, timeout=15, context=ctx) as resp:
            return json.load(resp).get("version", {}).get("number", "not captured")
    except Exception as exc:
        return f"not captured ({type(exc).__name__})"


ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
receipt_path = next(run_dir.glob("ART-07-01-*.json"), None)
testrun = "not captured"
# Sysmon/Agent versions are captured by the operator (guest-side); recorded verbatim
# only when present in the run directory as a note file.
note = run_dir / "provenance-notes.json"
extra = json.loads(note.read_text(encoding="utf-8")) if note.is_file() else {}

prov = {
    "repo_commit": git("rev-parse", "HEAD"),
    "repo_commit_subject": git("log", "-1", "--pretty=%s"),
    "working_tree_dirty": bool(git("status", "--porcelain")),
    "working_tree_diff_sha256": (git_diff_sha256() if git("status", "--porcelain")
                                 else "clean (no diff)"),
    "sysmon_config_sha256": sha256_file(ROOT / "config" / "sysmon-config.xml"),
    "rule_export_sha256": sha256_file(ROOT / "detections" / "exports" / "wmi-rules.ndjson"),
    "rules_live_in_kibana": extra.get("rules_live_in_kibana", "not captured"),
    "elasticsearch_version_observed": es_version(),
    "sysmon_version": extra.get("sysmon_version", "not captured"),
    "elastic_agent_version": extra.get("elastic_agent_version", "not captured"),
    "integration": extra.get("integration", "not captured"),
    "sink": {
        "receipt_file": receipt_path.name if receipt_path else "not captured",
        "receipt_sha256": sha256_file(receipt_path) if receipt_path else "not captured",
        "server": "scripts/sink_server.py (lab-interface bound, shared-token auth; "
                  "finalised receipts cannot be overwritten)",
    },
    "run_window_utc": ledger.get("run_window_utc", "not captured"),
    "run_started_utc": ledger.get("run_started_utc", "not captured"),
    "captured_utc": __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
ledger["provenance"] = prov
ledger_path.write_text(json.dumps(ledger, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps(prov, indent=2, ensure_ascii=False))
print("written to", ledger_path)
