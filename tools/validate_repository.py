#!/usr/bin/env python3
"""Offline packaging checks for WMI-LAB-1 (no Elasticsearch, no Windows runtime).

Covers: Sysmon XML syntax; detection export hygiene (11 rules, deterministic
ids, field coverage, no actions/creds); query file <-> export correspondence;
run ledgers valid against RUN-schema (stages, statuses, artifact hashes);
sink receipt integrity; sanitized-screenshot manifest hashes; local doc links;
secrets/credential-like strings; forbidden files in the repository.
Does not execute scenario code or validate EQL syntax.
"""
import hashlib
import json
import re
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import evidence_lib as el  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
UUIDV5_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$")


def query_fields(query):
    plain = re.sub(r"/\*.*?\*/", "", query, flags=re.S)
    return set(re.findall(r"\b(?:winlog|host|user|process|file|destination|event|registry)\.[A-Za-z0-9_.]+",
                          plain))


def normalize_eql(text):
    """Strip block comments and collapse whitespace so a query source and its export
    compare equal regardless of formatting; any predicate/character change fails."""
    body = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"\s+", " ", body).strip()


def validate():
    errors = []

    try:
        ET.parse(ROOT / "config/sysmon-config.xml")
    except ET.ParseError as exc:
        errors.append(f"Sysmon XML: {exc}")

    if (ROOT / "skills.md").exists():
        errors.append("Forbidden file in the repository: skills.md")

    # ---- detection export ---------------------------------------------------
    export = ROOT / "detections" / "exports" / "wmi-rules.ndjson"
    if not export.is_file():
        errors.append("missing detections/exports/wmi-rules.ndjson (run the generator first)")
        rules = []
    else:
        try:
            rules = el.parse_ndjson(export)
        except json.JSONDecodeError as exc:
            errors.append(f"rule export JSON: {exc}")
            rules = []
    if rules:
        ids = [r.get("rule_id") for r in rules]
        if len(rules) != 11:
            errors.append(f"expected 11 rules, got {len(rules)}")
        if len(set(ids)) != len(ids):
            errors.append("duplicate rule ids in export")
        for r in rules:
            i = r.get("rule_id") or ""
            if not UUIDV5_RE.match(i):
                errors.append(f"rule {r.get('name')}: id not the deterministic v5 shape")
            required_keys = {"rule_id", "name", "immutable", "rule_source", "enabled",
                             "interval", "from", "to", "description", "tags", "author",
                             "license", "threat", "related_integrations", "required_fields",
                             "setup", "note", "false_positives", "references", "risk_score",
                             "severity", "index", "query", "filters", "alert_suppression",
                             "type", "language", "actions"}
            missing_keys = required_keys - set(r)
            if missing_keys:
                errors.append(f"rule {r.get('name')}: missing export fields {sorted(missing_keys)}")
            if r.get("actions") not in (None, []):
                errors.append(f"rule {r.get('name')}: contains notification actions")
            if "meta" in r:
                errors.append(f"rule {r.get('name')}: environment metadata leaked")
            declared = {f.get("name") for f in r.get("required_fields", [])}
            missing = query_fields(r.get("query", "")) - declared
            if missing:
                errors.append(f"rule {r.get('name')}: undocumented fields {sorted(missing)}")
            setup = r.get("setup") or ""
            if "Detection basis:" not in setup or "docs/telemetry-contract.md" not in setup:
                errors.append(f"rule {r.get('name')}: setup lacks detection basis / contract reference")
            base = r.get("name", "").split("]")[0].lstrip("[")
            if base not in {"C1", "C2", "C3", "C4", "C5", "S1", "S2", "S3", "S4", "R1", "R2"}:
                errors.append(f"rule {r.get('name')}: unexpected id prefix {base!r}")

        shipped = {p.name for p in (ROOT / "detections" / "queries").glob("*.eql")}
        # each query file must map to exactly one export rule AND the exported query
        # must equal the .eql source (normalised) - drift in either direction fails.
        prefix_map = {
            "R1": "r1-ms-settings-open-command-registry-hijack",
            "C1": "c1-fodhelper-child-interpreter",
            "S1": "s1-script-host-fodhelper-cmd-parent",
            "S2": "s2-powershell-hidden-bypass-patterns",
            "C2": "c2-wmi-subscription-registration-sequence",
            "R2": "r2-wmi-subscription-registration-activation",
            "S3": "s3-system-shell-wmi-host-parent",
            "C3": "c3-wmi-hosted-interpreter-discovery",
            "C4": "c4-single-process-staging-archive",
            "S4": "s4-script-spawned-curl-upload-args",
            "C5": "c5-archive-created-then-deleted",
        }
        for r in rules:
            rid = r.get("name", "").split("]")[0].lstrip("[")
            fname = prefix_map.get(rid)
            if fname is None:
                errors.append(f"rule {r.get('name')}: no query-file mapping for id {rid!r}")
                continue
            qpath = ROOT / "detections" / "queries" / (fname + ".eql")
            if not qpath.is_file():
                errors.append(f"rule {r.get('name')}: missing query file {fname}.eql")
                continue
            if normalize_eql(qpath.read_text(encoding="utf-8")) != normalize_eql(r.get("query", "")):
                errors.append(f"rule {r.get('name')}: exported query differs from "
                              f"{fname}.eql (source/export drift)")
        expected_files = {v + ".eql" for v in prefix_map.values()}
        if shipped != expected_files:
            errors.append(f"query directory does not match the rule catalogue "
                          f"(extra={sorted(shipped - expected_files)}, "
                          f"missing={sorted(expected_files - shipped)})")

    # ---- run ledgers (nested: evidence/runs/RUN-<id>/RUN-<id>.json) ---------------
    runs_dir = ROOT / "evidence" / "runs"
    for ledger_path in sorted(runs_dir.glob("RUN-*/RUN-*.json")):
        try:
            ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"ledger {ledger_path.relative_to(ROOT)}: {exc}")
            continue
        for e in el.ledger_validate(ledger):
            errors.append(f"ledger {ledger_path.relative_to(ROOT)}: {e}")
        run_dir = ledger_path.parent
        for e in el.artifact_violations(ledger, run_dir):
            errors.append(f"ledger {ledger_path.relative_to(ROOT)}: {e}")
        for receipt in run_dir.glob("ART-07-01-*.json"):
            try:
                receipt_obj = json.loads(receipt.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                errors.append(f"receipt {receipt.relative_to(ROOT)}: malformed JSON")
                continue
            for e in el.receipt_validate(receipt_obj):
                errors.append(f"receipt {receipt.relative_to(ROOT)}: {e}")

    # ---- screenshots manifest ----------------------------------------------------
    shots = ROOT / "evidence" / "sanitized-screenshots"
    manifest_path = shots / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = manifest.get("images", [])
        names = [e.get("file") for e in entries]
        actual = {p.name for p in shots.glob("*.png")}
        if len(set(names)) != len(names) or set(names) != actual:
            errors.append("screenshot manifest does not match the image inventory")
        for e in entries:
            path = shots / e.get("file", "")
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != e.get("sha256"):
                errors.append(f"screenshot hash mismatch or missing: {e.get('file')}")
    except (OSError, ValueError, KeyError, TypeError):
        errors.append("screenshot manifest missing or malformed")

    # ---- secrets scan (values suppressed) ------------------------------------------
    token_pattern = re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b")
    # credential-like LITERAL assignment (quoted value); plain variable names
    # (password = os.environ...) and prose ("token = the ...") are not secrets.
    cred_pattern = re.compile(r"\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)"
                              r"\s*[=:]\s*[\"'][^\"']{6,}[\"']", re.I)
    text_paths = [ROOT / "README.md", ROOT / "CHANGELOG.md"]
    for folder in ("docs", "detections", "config", "payloads", "scripts", "evidence"):
        folder_path = ROOT / folder
        if folder_path.is_dir():
            text_paths.extend(x for x in folder_path.rglob("*")
                              if x.suffix.lower() in {".md", ".eql", ".ndjson", ".xml",
                                                      ".ps1", ".bat", ".html", ".json", ".py"})
    # phishing/ is a static delivery-page artifact; token-pattern scan only.
    text_paths.extend(x for x in (ROOT / "phishing").rglob("*")
                      if x.suffix.lower() in {".html", ".js"})
    for path in text_paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if token_pattern.search(text):
            errors.append(f"Potential bot credential in {path.relative_to(ROOT)} (value suppressed)")
        if path.suffix.lower() not in {".ndjson", ".json"} and cred_pattern.search(text):
            errors.append(f"Credential-like assignment in {path.relative_to(ROOT)} (value suppressed)")

    # ---- local doc links -------------------------------------------------------------
    for path in [ROOT / "README.md", ROOT / "CHANGELOG.md",
                 *sorted((ROOT / "docs").rglob("*.md")),
                 *sorted((ROOT / "scripts").rglob("*.md")),
                 *sorted((ROOT / "payloads").rglob("*.md")),
                 *sorted((ROOT / "evidence").rglob("*.md"))]:
        for target in re.findall(r"\[[^\]]*\]\(([^\s)]+)\)", path.read_text(encoding="utf-8")):
            if target.startswith(("https://", "http://", "mailto:", "#")):
                continue
            if not (path.parent / target.split("#")[0]).exists():
                errors.append(f"Broken local link in {path.relative_to(ROOT)}: {target}")

    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        return 1
    print("PASS: Sysmon XML, detection export (11 deterministic rules), run ledgers + "
          "receipts, screenshot manifest, secret scan, doc links.")
    print("NOT VALIDATED: Sysmon runtime/schema, Elastic import/EQL execution, "
          "detection accuracy, Git-history secrets.")
    return 0


if __name__ == "__main__":
    sys.exit(validate())