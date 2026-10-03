#!/usr/bin/env python3
"""Pure evidence helpers shared by the verifier and the offline tests.

No network, no credentials. Canonical-hash, ledger and receipt logic lives here so
the acceptance rules are unit-testable without an Elasticsearch instance.
"""
import hashlib
import json
import re
from pathlib import Path

RUN_ID_RE = re.compile(r"^RUN-[0-9]{8}-[0-9]{2,}$")
ART_ID_RE = re.compile(r"^ART-[0-9]{2}-[0-9]{2}$")
STAGE_RE = re.compile(r"^S[1-7](b)?$")
STATUSES = ("NOT RUN", "PARTIAL", "PASS", "SENSOR GAP", "INGEST/MAPPING GAP",
            "PREVENTED", "DENIED", "CHAIN BROKEN")
REF_KINDS = ("event", "register", "receipt", "artifact", "rule", "scorecard",
             "decision", "session", "impact")
BINARY_EXTENSIONS = (".zip", ".7z", ".docm", ".exe", ".dll", ".jpg", ".png")


def canon_sha256(data: bytes) -> str:
    """Canonical hash: sha256 over CRLF->LF normalised bytes (text artifacts)."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest().upper()


def ts_within(recorded: str, actual: str, tolerance_s: float = 5.0):
    """True if recorded and actual ISO-8601 Z timestamps differ by <= tolerance.

    Used by the verifier to re-verify a ledger event ref against the event re-read
    from Elasticsearch (the index is the source of truth; the ledger row must agree).
    Returns None when either value is not a parseable ISO-8601 Z timestamp.
    """
    from datetime import datetime, timezone
    try:
        a = datetime.fromisoformat(recorded.replace("Z", "+00:00")).astimezone(timezone.utc)
        b = datetime.fromisoformat(actual.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None
    return abs((a - b).total_seconds()) <= tolerance_s


def raw_sha256(data: bytes) -> str:
    """Raw-byte hash for binary artifacts (zip etc.), where LF-normalising corrupts."""
    return hashlib.sha256(data).hexdigest().upper()


def artifact_hash(path: Path) -> str:
    data = path.read_bytes()
    return raw_sha256(data) if path.suffix.lower() in BINARY_EXTENSIONS else canon_sha256(data)


# --- ledger validation -------------------------------------------------------

def ledger_validate(ledger: dict):
    """Return a list of violations. Empty list == structurally valid.

    Mirrors evidence/runs/RUN-schema.json with stdlib-only checks.
    """
    errors = []
    if not isinstance(ledger, dict):
        return ["ledger is not an object"]
    if not RUN_ID_RE.match(ledger.get("run_id") or ""):
        errors.append("run_id does not match RUN-YYYYMMDD-<seq>")
    if ledger.get("scenario_id") != "WMI-LAB-1":
        errors.append("scenario_id != WMI-LAB-1")
    if ledger.get("secrets_policy") != "no-secrets-allowed":
        errors.append("secrets_policy != no-secrets-allowed")
    created = ledger.get("created_utc") or ""
    if not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$", created):
        errors.append("created_utc is missing or not an ISO-8601 Z timestamp")
    stages = ledger.get("stages")
    if not isinstance(stages, list) or not stages:
        errors.append("stages missing or empty")
    else:
        seen = set()
        for s in stages:
            if not isinstance(s, dict):
                errors.append("stage row is not an object")
                continue
            if not STAGE_RE.match(s.get("stage") or ""):
                errors.append(f"invalid stage id {s.get('stage')!r}")
            if s.get("status") not in STATUSES:
                errors.append(f"stage {s.get('stage')}: invalid status {s.get('status')!r}")
            if s.get("status") == "NOT RUN" and not (s.get("notes") or "").strip():
                errors.append(f"stage {s.get('stage')}: NOT RUN requires an explicit note")
            for key in ("input_artifacts", "output_artifacts"):
                if not isinstance(s.get(key), list):
                    errors.append(f"stage {s.get('stage')}: {key} must be a list")
            for ref in s.get("evidence_refs") or []:
                if not isinstance(ref, dict) or ref.get("kind") not in REF_KINDS:
                    errors.append(f"stage {s.get('stage')}: invalid evidence_ref kind {ref!r}")
            seen.add(s.get("stage"))
        # A full run must have every S1..S7 row; missing rows are violations.
        for n in range(1, 8):
            if f"S{n}" not in seen:
                errors.append(f"missing stage row S{n}")
    idx = ledger.get("artifact_index")
    if not isinstance(idx, list):
        errors.append("artifact_index missing or not a list")
    else:
        for a in idx:
            if not isinstance(a, dict):
                errors.append("artifact_index row is not an object")
                continue
            if not ART_ID_RE.match(a.get("artifact_id") or ""):
                errors.append(f"invalid artifact_id {a.get('artifact_id')!r}")
            if not re.match(r"^[0-9A-F]{64}$", a.get("sha256") or ""):
                errors.append(f"artifact {a.get('artifact_id')}: sha256 not 64 uppercase hex")
    known = {"run_id", "scenario_id", "created_utc", "secrets_policy", "notes",
             "stages", "artifact_index"}
    extra = set(ledger) - known
    if extra:
        errors.append(f"unexpected top-level keys: {sorted(extra)}")
    # stage rows: reject unknown keys beyond the schema set
    stage_keys = {"stage", "host", "account", "status", "input_artifacts",
                  "output_artifacts", "evidence_refs", "rollback_status", "notes"}
    for s in stages:
        if isinstance(s, dict):
            extra = set(s) - stage_keys
            if extra:
                errors.append(f"stage {s.get('stage')}: unexpected keys {sorted(extra)}")
    idx_keys = {"artifact_id", "path", "sha256", "producer_stage", "consumer_stage"}
    for a in idx:
        if isinstance(a, dict):
            extra = set(a) - idx_keys
            if extra:
                errors.append(f"artifact {a.get('artifact_id')}: unexpected keys {sorted(extra)}")
    return errors


def artifact_violations(ledger: dict, run_dir: Path):
    """Check every artifact_index entry exists and its hash matches."""
    errors = []
    for a in ledger.get("artifact_index") or []:
        p = run_dir / a.get("path", "")
        if not (run_dir / a["path"]).is_file() and not p.is_file():
            errors.append(f"artifact file missing: {a.get('path')}")
            continue
        if artifact_hash(run_dir / a["path"]) != a.get("sha256"):
            errors.append(f"artifact hash mismatch: {a.get('path')}")
    return errors


# --- sink receipt / transfer integrity --------------------------------------

def receipt_validate(receipt: dict):
    """Structural + equality checks for the sink receipt (ART-07-01)."""
    errors = []
    if not isinstance(receipt, dict):
        return ["receipt is not an object"]
    if receipt.get("kind") != "transfer-receipt":
        errors.append("receipt kind != transfer-receipt")
    payload = receipt.get("payload")
    if not isinstance(payload, dict):
        return errors + ["receipt payload missing"]
    if not RUN_ID_RE.match(payload.get("run_id") or ""):
        errors.append("receipt run_id missing/invalid")
    if not payload.get("host"):
        errors.append("receipt host missing")
    files = payload.get("sink_files") or []
    if not isinstance(files, list) or not files:
        errors.append("receipt sink_files empty or missing (transfer FAIL)")
    for f in files:
        for key in ("name", "size", "sha256"):
            if key not in f:
                errors.append(f"receipt sink file {f.get('name')} missing {key}")
    return errors


def manifest_hash_of(receipt: dict):
    """Canonical hash the server recorded for the in-guest manifest snapshot."""
    payload = receipt.get("payload") or {}
    text = payload.get("manifest_text") or ""
    return canon_sha256(text.encode("utf-8")) if text else None


# --- rule export helpers -----------------------------------------------------

def parse_ndjson(path: Path):
    rules = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        item = json.loads(line)
        item["_line"] = number
        rules.append(item)
    return rules


def rule_id_uniqueness(rules):
    ids = [r.get("rule_id") for r in rules]
    return [i for i, x in enumerate(ids) if x is None or ids.count(x) > 1]