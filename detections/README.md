# detections — Rule suite C1–C5, S1–S4, R1–R2 (WMI-LAB-1)

Elastic EQL detections engineered against the WMI persistence + UAC bypass kill chain.
All rules follow the same conventions:

- **Deterministic `rule_id`** = SHA-256("WMI-LAB:" + rule name) rendered as a UUID
  (v5 shape) — re-imports overwrite instead of duplicating; rename ⇒ delete the old
  rule server-side, then import.
- **Building blocks**: every rule carries `building_block_type=default` (hidden from
  the default alert view, feeds correlation). No single signal asserts an incident;
  conclusions come from the run ledger + verifier.
- EQL on Sysmon (`logs-windows.sysmon_operational-*`, `winlog.channel =
  Microsoft-Windows-Sysmon/Operational`); interval 1 m, look-back 2–3 m per rule;
  suppression on host/entity groups (independent executions are not merged).
- Detection basis (MITRE detection strategy + Sigma rule id) is in each rule's
  `setup`; every rewrite below is traced to the run-window evaluation and the review
  round (see CHANGELOG.md).
- Rebuild + import: `powershell scripts/rules/gen_rules_ndjson.ps1` → `curl -F
  "file=@detections/exports/wmi-rules.ndjson" -u elastic:... <kibana>/api/
  detection_engine/rules/_import?overwrite=true` (after deleting any prior imports).

## Rule index (11 rules — building blocks)

| Rule | Name | Risk | Supp | EQL scope / fires at | Detection basis |
|---|---|---|---|---|---|
| **R1** | ms-settings Open Command Registry Hijack | 47 | host (60 s) | EID 13, `registry.path` under `ms-settings\Shell\Open\command` + value (Default/DelegateExecute); S2 | Sigma `46dd5308`; MITRE DET0388 (registry half) |
| **C1** | Fodhelper Child Interpreter | 73 | host+entity (30 s) | EID 1, fodhelper parent of listed interpreter; S2 | Sigma `7f741dcf`; DET0388 (process half) |
| **S1** | Script Host With Fodhelper or Cmd Parent | 47 | host+entity (30 s) | EID 1, wscript/cscript; S2 | Sigma `7f741dcf` family; overlaps C1 |
| **S2** | PowerShell Hidden and Bypass or Encoded Command Patterns | 47 | host+user (60 s) | EID 1: hidden AND (bypass/unrestricted) OR encoded; S2/S4 | Sigma PS flag corpus; T1059.001 |
| **C2** | WMI Subscription Registration Sequence | 73 | host+computer (30 s) | Sequence 19→20→21 Created; S3 | Sigma `0f06a3a5`; DET0086/AN0236 |
| **R2** | WMI Subscription Registration Followed by WMI-Hosted Interpreter | 73 | host (600 s) | Sequence: any 19/20/21 Created → WMI-hosted interpreter (10 m); S3/S4 | MITRE DET0086/AN0236 (reg→activation pair) |
| **S3** | SYSTEM Shell or Tool With WMI Host Parent | 73 | host+entity (60 s) | EID 1 SYSTEM, parent WmiPrvSE/scrcons; S4 | DET0086/AN0236; Sigma `sysmon_wmi_susp_scripting` |
| **C3** | WMI-Hosted Interpreter Followed by Discovery Process | 73 | host (60 s) | Sequence with per-clause `by`: interpreter `process.entity_id` → discovery `process.parent.entity_id` (30 s) | DET0086/AN0236 + T1082/T1016 |
| **C4** | Staging and Archive Creation by a Single Process | 73 | host+entity (120 s) | Sequence EID 11: non-archive create → zip create, same `process.entity_id`; S5/S6 | T1005/T1074.001/T1560.001 |
| **S4** | Script-Spawned Curl with Upload Arguments | 73 | host+entity (60 s) | EID 1: curl spawned by a script/interpreter with upload-intent args; S6 | **lab analogue** of upload intent (T1041 deliberately NOT asserted) |
| **C5** | Archive Creation Followed by Archive Deletion | 73 | host (60 s) | Sequence with per-clause `by file.path`: EID 11 zip → EID 23 zip of the SAME path (2 m) | T1070.004 |

EQL scope notes (corrected 2026-10-03): Elasticsearch 9.5.3 **supports a per-clause
`by` key**: C3 joins the interpreter's `process.entity_id` → discovery's
`process.parent.entity_id` (both keyed with `host.name`) and C5 joins the zip create →
zip delete by `file.path` (also `host.name`) — cross-host same-path false joins are
impossible. Curl E1↔E3 ownership stays a verifier/ledger join (entity key), and the
acceptance verifier re-checks ancestry and path equality from the ledger — see
`docs/correlation-architecture.md`.

## Run coverage — RUN-20261003-03 (two distinct counts)

Stored alerts and unique clusters are different quantities and are reported
separately. **Stored alerts** are upper bounds (1 m schedule / 2 m look-back re-alert
the same cluster across evaluations; the exported per-alert ids/timestamps are in
`evidence/runs/RUN-20261003-03/alert-manifest.json`). **Unique clusters** are the
direct EQL re-evaluation of the run window (one behaviour per rule, R1/S2 two).

| Rule | Unique clusters | Stored alerts |
|---|---|---|
| R1 | 2 | 2 |
| C1 | 1 | 1 |
| S1 | 1 | 1 |
| S2 | 2 | 2 |
| C2 | 1 | 4 |
| R2 | 1 | 3 |
| S3 | 1 | 1 |
| C3 | 1 | 3 |
| C4 | 1 | 3 |
| S4 | 2 | 2 |
| C5 | 1 | 3 |
| **Total** | **14 unique clusters** | **25 stored alerts** |

Neither number means "14/25 behaviours": stored alerts re-match the same cluster
across evaluations (see the manifest timestamps), and unique clusters are per-rule
sequence/event matches, not distinct attack steps (overlaps C1/S1 and S2/S3/R2 are
documented).

Control window (2026-10-03 10:00–10:05Z, idle, 5 minutes): **0 matches for all 11
rules** — a short negative check, NOT a false-positive rate or precision claim.

## Rule-authoring notes

- EID 19/20/21 events have `event.category: wmi` — use `[any where ...]`; EID 13 maps
  to ECS `registry.path` / `registry.value` on this stack (`winlog.event_data.TargetObject`
  is unmapped); EID 11/23 carry `process.entity_id` but no `process.parent` here.
- Case-insensitive comparisons use `:` (scalars and lists) and `like~` (wildcards);
  `in`/`like` are case-sensitive and are avoided for process/path names.
- EQL per-clause `by` (ES 9.5.3) supports a field list per step, including different
  fields per step and `host.name` alongside join keys (C3, C5). Object references
  (WMI bindings, receipt↔artifact) cannot be carried by the queries and live in the
  verifier.
- **Building blocks**: 10 of the 11 rules export with
  `building_block_type=default` (hidden from the default Alerts view; they feed
  analysis). **S4 is exported WITHOUT that flag** - the upload-intent/exfil-analogue
  signal is the one alert an analyst should see by default. If a future SOC
  correlation tier consumes the blocks, add that rule here and document it.
- Adding a rule requires BOTH the `.eql` file and a metadata block in
  `scripts/rules/gen_rules_ndjson.ps1` — an unloaded query imports silently and fails
  at execution with an empty query.

See `docs/correlation-architecture.md` for join keys and evidence tiers, and
`docs/attack-chain-plan.md` for per-stage boundaries.