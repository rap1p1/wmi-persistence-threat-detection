# docs — Canonical technical records

Flat set of design/analysis documents for the WMI persistence + UAC bypass lab.
Design-intent documents are labelled as such; recorded results live in run ledgers
and reports.

| Document | Contents |
|---|---|
| [attack-chain-plan.md](attack-chain-plan.md) | The canonical S1–S7 chain: commands, expected telemetry, evidence and boundaries per stage, gates. |
| [architecture.md](architecture.md) | Lab topology (single victim host + lab host), Sysmon/Elastic telemetry path, internal sink. |
| [correlation-architecture.md](correlation-architecture.md) | Detection correlation design: join keys (entity, WMI references, transfer hashes), evidence tiers, sensor/ingest checklist. |
| [telemetry-contract.md](telemetry-contract.md) | Field dependencies, event semantics, scheduling and suppression of the rule export (updated for the C3/C4/C5/S4 rewrites). |
| [scenario-analysis.md](scenario-analysis.md) | Historical analysis of the original artifacts and technique scope. |
| [case-study.md](case-study.md) | Historical evidence assessment of the 2026-04 screenshots (archived, not run evidence). |
| [attack-detection-mapping.md](attack-detection-mapping.md) | **Historical** behavior → rule mapping (pre-2026-10-03 rule set); current rules are in `../detections/README.md`. |

Traceability: every stage in `attack-chain-plan.md` maps to a rule in
`../detections/README.md` and to acceptance assertions in
`../scripts/verify/verify_run_evidence.py`.