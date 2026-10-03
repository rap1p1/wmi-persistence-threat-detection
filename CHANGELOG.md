# Change record

## 2026-10-03 — evidence architecture and repository restructure (Phase 0–2)

Driven by the Phase 0 gap audit (detection basis missing repo-wide; no run-scoped
evidence; no acceptance verifier; join keys undocumented; C1 lacked the registry
stage; no activation stage; C4/C5 curl-vs-PowerShell mismatch; severity/tag
inflation). Every change below maps to a finding in that audit:

- **Phase 1 — evidence architecture**
  - Added `evidence/runs/RUN-schema.json`: run ledger with `additionalProperties:
    false`, explicit `NOT RUN` statuses, event rows carrying real `es_id` +
    `@timestamp`, artifact index with canonical/raw hashes.
  - Added `scripts/verify/verify_run_evidence.py`: per-stage acceptance assertions,
    fail-fast on unknown runs, `--all` regression, transfer-receipt integrity;
    `scripts/verify/fetch_evidence_ids.py`: ES event fetch for ledger rows;
    `scripts/evidence_lib.py`: pure, testable evidence helpers.
  - Added `docs/correlation-architecture.md`: join keys (process `entity_id`
    ancestry; EID 21 binding references ⇄ 19/20 names; transfer hash equality),
    evidence tiers (DIRECT / SUPPORTED HANDOFF / TEMPORAL-CONTEXTUAL / UNPROVEN /
    CONTRADICTED), sensor/ingest checklist.
  - Added `docs/attack-chain-plan.md` (S1–S7 with per-stage telemetry, evidence and
    explicit boundaries) and `docs/architecture.md` (single-host topology, sink).
- **Phase 2 — restructure to the reference layout**
  - Layout: `docs/`, `evidence/runs/RUN-<date>-<seq>/`, `detections/` (catalogue +
    `queries/*.eql` + `exports/*.ndjson`), `reports/`, `scripts/tests/`,
    `payloads/`; historical screenshots moved to `evidence/sanitized-screenshots/`
    (provenance only, not run evidence).
  - `scripts/rules/gen_rules_ndjson.ps1`: deterministic export (rule_id =
    SHA-256(name), v5 shape); 11 rules = 9 historical predicates preserved
    verbatim + 2 new: R1 (ms-settings registry stage, closes the UAC coverage gap;
    basis Sigma `46dd5308`) and R2 (notepad-triggered consumer activation, closes
    the activation coverage gap; basis MITRE DET0086/AN0236).
  - Detection basis added to every rule's `setup` (MITRE detection strategy + Sigma
    rule ids + vendor references); severities/tags normalised to the building-block
    taxonomy (historical "Critical"/"High Fidelity" tags dropped).
  - Payloads split and simplified: `payloads/setup.bat` (entry + UAC bypass),
    `payloads/install.ps1` (consumer materialisation with run-scoped config +
    run-id read-back check + idempotent WMI registration), `payloads/consumer.ps1`
    (discovery/collection/archive/exfil/cleanup). Exfil now targets the internal
    sink (`scripts/sink_server.py`) with an ART-07-01 receipt — Telegram and other
    external channels are out of scope by design.
  - Added `scripts/tests/test_offline.py` (rule-id uniqueness/determinism, ledger
    schema negative cases, verifier negative cases, receipt negatives) and rewrote
    `tools/validate_repository.py` + CI for the new layout.

## VM readiness checklist (Phase 3 gate — confirmed before the first run)

1. Victim VM: Windows 10/11 Pro, workgroup; victim account = local Administrators
   member running with a filtered (medium-integrity) token. No AD.
2. Sysmon installed with `config/sysmon-config.xml`; **prove** EID 1/3/11/13/19/20/21
   /23 reach the channel locally AND in Elastic (per-run probe; the empty
   `<WmiEvent onmatch="exclude">` block must be shown not to suppress 19/20/21;
   check E255/ingest errors).
3. Elastic Agent enrolled and shipping Sysmon + Security channels to the lab's
   Elastic stack; ES creds to the operator via environment only.
4. Clock: guest UTC aligned with the lab host (one probe artifact per run).
5. VM snapshot taken before the run; cleanup probe (ART-08-01) after.
6. Exfil channel configured to the internal sink (repo host, port documented per
   run); no external services.

## 2026-09-25 — rule metadata and telemetry corrections

- Replaced all nine embedded setup guides, including stale fallback claims, unsupported false-positive claims, outdated configuration descriptions and incorrect Sysmon deletion guidance.
- Renamed rules to describe their actual event patterns; retained prefixes and rule_id values for historical traceability. Incremented metadata versions.
- Added field dependency metadata and a telemetry contract covering event categories, actor context, token/integrity distinctions, archive/file hashes, suppression and scheduling.
- Corrected query comments while preserving executable query predicates, schedules, suppression, severity and ATT&CK tags.
- Documented delivery provenance gaps, generated-file matches in C4, and cleanup evidence boundaries.
- Added offline checks for field coverage, event-source descriptions and known overclaim regressions. Live correlation attribution and timing still require source events; this update does not claim to resolve them.

## 2026-09-25 — attack-to-detection mapping

- Removed the prospective validation plan and blank run-record template from the published documentation.
- Added a behavior-to-telemetry-to-rule mapping with links to retained evidence, process/object relationships, and overlapping rule coverage.
- Replaced the README technique list with a concise mapping of implemented detection work and observed alerts.
- Preserved scenario code, rule queries, and evidence images unchanged.

## 2026-09-25 — evidence-based documentation refresh

Baseline: `43a7141c7753058e58bfb0894d4123236ce3d1b9`.

- Replaced the Word report with a Markdown case study, a partial UTC event timeline, and an explicit telemetry-coverage assessment.
- Retained seven selected original screenshots unchanged, with source-image provenance and SHA-256 values. Removed the Word file from the current tree; its historical version remains in Git.
- Rewrote README around implemented behaviors, observed results, and verified scope. Added static scenario analysis and a source map.
- Removed the unimplemented playbook, duplicated limitations document, and unsupported performance/AV-evasion claims. Separated measured observations from unverified claims.
- Corrected the malformed Sysmon XML comment without changing filter conditions.
- Removed notification actions/connectors and environment-specific export metadata. Owner-side credential rotation is still required.
- Aligned descriptions, false-positive caveats, and notes with query scope. Preserved rule IDs, queries, names, enabled state, schedules, severity, filters, and original ATT&CK tags.
- Added offline validation and CI. Scenario scripts and the delivery page remain byte-for-byte unchanged.

## Verification scope

Offline checks cover XML syntax, NDJSON rule inventory, export hygiene, documentation links, and evidence hashes. Comparisons against the baseline check preservation of executable artifacts and detection queries. Windows configuration acceptance, Elastic import/EQL execution, detection accuracy, and response remain unvalidated by these checks.
