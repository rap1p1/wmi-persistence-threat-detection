# WMI Persistence + UAC Bypass — Evidence-Driven Detection Lab

A personal-host (workgroup, no domain) lab that replays a local intrusion chain —
normal user runs a script → fodhelper UAC bypass → WMI event-subscription
persistence → activation → discovery/collection/archive → exfiltration to an internal
sink → cleanup — and evaluates it with Elastic Security EQL rules under the same
evidence discipline as the reference C0015 lab: every claim maps to a run ledger row
with a real Elasticsearch `_id` + `@timestamp`, and acceptance is decided by an
offline verifier, not by prose.

**Windows 10/11 · Sysmon · Elastic Agent · Elasticsearch/Kibana · EQL**

## Status

- Phase 0 gap audit: complete (2026-10-03) — detection-basis, coverage and overclaim
  gaps identified and closed by design (see CHANGELOG.md).
- Phase 1 evidence architecture + Phase 2 restructure: implemented in this tree
  (layout below). Offline tests and repository validation pass.
- Phase 3 verified run: **pending the lab VM** — see `scripts/runbooks/README.md`
  and the VM readiness checklist in CHANGELOG.md. No acceptance claim is made until a
  run ledger exists and the verifier says ACCEPTED.
- The April-2026 screenshots are archived as **historical material**, not run
  evidence: `evidence/sanitized-screenshots/`.

## The chain and its rules

| Stage (docs/attack-chain-plan.md) | Technique | Observable telemetry | Rules |
|---|---|---|---|
| S1 Entry (user starts `setup.bat`) | — (declared operator action) | E1 cmd | — |
| S2 UAC bypass (`ms-settings` hijack → fodhelper → script host → elevated PS) | T1548.002, T1059.005/.001 | EID 13 registry, E1 fodhelper/wscript/PS | R1, C1, S1, S2 |
| S3 WMI persistence install (filter/consumer/binding) | T1546.003 | EID 11 consumer, EID 19/20/21 | C2 |
| S4 Activation (notepad fires the filter → consumer under WmiPrvSE, SYSTEM) | T1546.003 | E1 notepad, E1 WmiPrvSE→PS | R2, S3, C3 |
| S5 Discovery + collection + staging + manifest | T1082/T1016/T1005/T1074.001 | E1 arp, EID 11 staging | C3, C4 (stage 1) |
| S6 Archive + exfil to the internal sink (curl) + PS status | T1560.001, T1567 surrogate | EID 11 zip, E1/E3 curl, E3 PS, sink receipt | S4, C4 (status channel), receipt |
| S7 Cleanup | T1070.004 | E1 cmd, EID 23 | C5 |

Detailed join keys and evidence tiers: `docs/correlation-architecture.md`.
Per-rule detection basis (MITRE detection strategy + Sigma rule ids + vendor
references): `detections/README.md` and each rule's `setup` in the export.

## Repository structure

| Location | Purpose |
|---|---|
| `docs/` | architecture, attack-chain-plan, correlation-architecture, telemetry contract, historical analysis |
| `evidence/runs/` | run ledgers (`RUN-schema.json` + one dir per run) |
| `evidence/sanitized-screenshots/` | historical screenshots (not run evidence) |
| `detections/` | rule catalogue + `queries/*.eql` + `exports/*.ndjson` (deterministic export) |
| `payloads/` | run-scoped scenario artifacts (`setup.bat`, `install.ps1`, `consumer.ps1`) |
| `reports/` | one report per re-run of the chain (§5 skeleton) |
| `scripts/` | evidence helpers, verifier, ES fetch helper, sink server, rule generator, runbook, offline tests |
| `tools/` | offline repository validator |
| `config/` | Sysmon telemetry configuration |
| `phishing/` | original delivery-page artifact (historical, out of scope for evidence) |
| `.github/workflows/` | CI: offline tests + repository validation |

## How to operate

1. Prepare the lab per `scripts/runbooks/README.md` (VM snapshot, Sysmon installed and
   ingest-verified, sink started, run-scoped config built).
2. Run the chain (operator runbook) and capture per-stage evidence with
   `scripts/verify/fetch_evidence_ids.py` into the run ledger.
3. Verify: `python scripts/verify/verify_run_evidence.py <RUN-<date>-<seq>>` →
   ACCEPTED. Regress all runs with `--all`.
4. Write the report under `reports/` (context → timeline → per-stage evidence table →
   volume split → limitations → references).

Offline checks (no Elasticsearch needed):

```sh
python scripts/tests/test_offline.py
python tools/validate_repository.py
```

These cover rule-id uniqueness and determinism, ledger-schema negative cases,
verifier negative cases, transfer-receipt integrity, export hygiene and local doc
links. They do not execute the scenario or validate Windows behavior.

## Evidence scope

No verified run is recorded in this tree yet; nothing here is presented as a detected
incident. Historical screenshots are provenance for the earlier analysis only. The
original connector credential exposure is a released-lab record: rotation and
historical review remain the owner's task (see CHANGELOG.md).