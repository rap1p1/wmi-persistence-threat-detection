# Reference Run Report — RUN-20261003-03

Window: 2026-10-03 11:36:00Z – 11:39:30Z. Ledger + artifacts:
`evidence/runs/RUN-20261003-03/`. Verifier:
`scripts/verify/verify_run_evidence.py RUN-20261003-03` → **ACCEPTED**
(ES re-verification, 56 events). Rules live in Kibana = the **final 11-rule export**
(including the redesigned E1-only S4), so detection numbers are **stored alerts**.

## 1. Context / scope

Same personal-host lab (victim `wmi`, operator-launched via vmrun, High integrity —
mechanism replay as documented). Sysmon 15.21 + repo config, internal sink
192.168.106.1:9180. Key change vs run-02: **E3 attribution is resolved by process
ENTITY** (Sysmon emits the curl E3 with `Image: <unknown process>` — process.name
empty — but with the correct `process.entity_id`); the verifier joins E1↔E3 by entity
and records a GAP only when the entity is also missing.

## 2. Timeline (real event times)

| Time (Z) | Observation |
|---|---|
| 11:36:25 | S1 — `setup.bat` (operator action) |
| 11:36:27.732 / .744 / .769 | S3 — EID 19/20/21 Created (gate PASS) |
| 11:36:43 | S4 — notepad → consumer under WmiPrvSE (SYSTEM) |
| 11:36:4x | S6 — curl PUT (zip + manifest) → E3 :9180; PS status E3 |
| 11:36:5x | S7 — EID 23 wdmp.zip (same path, verifier) |
| 11:37:17–19 | First stored alerts (all rules) |

## 3. Per-stage evidence table

| Stage | Status | Evidence | Boundary / note |
|---|---|---|---|
| S1–S2 | PASS | cmd; EID 13 ms-settings; fodhelper→wscript→ps | ancestry verifier-checked; registry→fodhelper TEMPORAL |
| S3 | PASS | EID 19/20/21 Created 11:36:27; svhw.ps1 write; guest hash `84130A62…` == staged consumer | module integrity; binding refs verifier-checked |
| S4 | PASS | notepad → consumer (WmiPrvSE, SYSTEM) | activation |
| S5 | PASS | ARP (SYSTEM) + info.txt/_manifest.txt staging | in-process queries not independently evidenced |
| S6 | PASS | zip create; curl E1 x2; curl E3 :9180 (**entity-matched**, name-less); PS status E3; receipt `ART-07-01` (wdmp.zip 14661 B) | **E3 ownership by entity** verified; transfer by receipt |
| S7 | PASS | EID 23 wdmp.zip; create/delete same path | cleanup verified (`ART-08-01`) |

## 4. Detection results — live stored alerts

| Rule | Unique clusters (EQL) | Stored alerts (upper bound) | Notes |
|---|---|---|---|
| R1 | 2 | 2 | ms-settings (Default + DelegateExecute) |
| C1 | 1 | 1 | wscript under fodhelper |
| S1 | 1 | 1 | same event as C1 (overlap) |
| S2 | 2 | 2 | install PS + consumer PS (overlap with S3/R2) |
| C2 | 1 | 4 | registration cluster re-alerted across 1 m evaluations |
| R2 | 1 | 3 | registration → WMI-hosted interpreter |
| S3 | 1 | 1 | consumer powershell |
| C3 | 1 | 3 | interpreter → discovery (ancestry verifier-checked) |
| C4 | 1 | 3 | staging → archive by the consumer entity |
| S4 | 2 | 2 | **script-spawned curl upload intent (E1-only) — fired on this run** |
| C5 | 1 | 3 | archive create → delete, same path (verifier) |

**14 unique clusters; 25 stored alerts.** Stored-alert counts are **upper bounds**
(1 m interval / 2 m lookback re-match the same cluster; suppression bounds within-run
merging). None implies distinct incidents (building-block mode).

## 5. Limitations (honest)

- Operator-launched High-integrity session; UAC mechanism replayed (S4's SYSTEM
  consumer is the elevation-path evidence).
- Sysmon E3 for the short-lived curl is emitted with `Image: <unknown process>`; the
  ownership is therefore proven by `process.entity_id` (matching the curl E1), with
  the name-less condition annotated. This is a Sysmon-local attribution limitation
  (now documented, not a blocking gap).
- Alerts reflect schedule/lookback re-matching; unique clusters are the behavior count.
- EQL asymmetric joins (ancestry/ownership/path) enforced by the verifier (ES 9.5.3
  limitation documented in `docs/correlation-architecture.md`).
- No reboot-survival test; subscription left installed by design.

## 6. Recovery / cleanup

- Snapshot `before-run-20261003-03`; guest verified clean of `wdmp.zip`/`wdmp`;
  subscription re-installed by design; sink stopped after evidence.

## 7. References

- Ledger + artifacts: `evidence/runs/RUN-20261003-03/`
- Rules: `detections/README.md` · joins: `docs/correlation-architecture.md`
- Verifier: `scripts/verify/verify_run_evidence.py` · builder: `scripts/build_ledger_run.py`