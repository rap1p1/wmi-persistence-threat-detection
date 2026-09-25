# Change record

## 2026-09-25 — evidence-based documentation refresh

Baseline: `43a7141c7753058e58bfb0894d4123236ce3d1b9`.

- Replaced the Word report with a Markdown case study, a partial UTC event timeline, and an explicit telemetry-coverage assessment.
- Retained seven selected original screenshots unchanged, with source-image provenance and SHA-256 values. Removed the Word file from the current tree; its historical version remains in Git.
- Rewrote README around implemented behaviors, observed results, and verified scope. Added static scenario analysis and a source map.
- Removed the unimplemented playbook, duplicated limitations document, and unsupported performance/AV-evasion claims. Labeled future validation as planned work.
- Corrected the malformed Sysmon XML comment without changing filter conditions.
- Removed notification actions/connectors and environment-specific export metadata. Owner-side credential rotation is still required.
- Aligned descriptions, false-positive caveats, and notes with query scope. Preserved rule IDs, queries, names, enabled state, schedules, severity, filters, and original ATT&CK tags.
- Added offline validation and CI. Scenario scripts and the delivery page remain byte-for-byte unchanged.

## Verification scope

Offline checks cover XML syntax, NDJSON rule inventory, export hygiene, documentation links, and evidence hashes. Comparisons against the baseline check preservation of executable artifacts and detection queries. Windows configuration acceptance, Elastic import/EQL execution, detection accuracy, and response remain unvalidated by these checks.
