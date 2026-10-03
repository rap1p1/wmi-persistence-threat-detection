# detections — Rule suite C1–C5, S1–S4, R1–R2 (WMI-LAB-1)

Elastic EQL detections engineered against the WMI persistence + UAC bypass kill chain.
All rules follow the same conventions:

- **Deterministic `rule_id`** = SHA-256("WMI-LAB:" + rule name) rendered as a UUID
  (v5 shape) — re-imports overwrite instead of duplicating; rename ⇒ delete the old
  rule server-side, then import.
- EQL on Sysmon (`logs-windows.sysmon_operational-*`, `winlog.channel =
  Microsoft-Windows-Sysmon/Operational`); interval 1 m, look-back 2–3 m per rule;
  alert suppression on host/entity groups.
- Every rule carries its **detection basis** in `setup` (MITRE detection strategy +
  Sigma rule id + vendor reference) — reviewers can trace why the predicate looks the
  way it does.
- Rebuild + import: `powershell scripts/rules/gen_rules_ndjson.ps1` → `curl -F
  "file=@detections/exports/wmi-rules.ndjson" -u elastic:... <kibana>/api/
  detection_engine/rules/_import?overwrite=true` (after deleting any prior imports).

## Rule index (11 rules)

### Signal / alerting tiers

| Rule | Name | Risk | Supp | Fires at | Detection basis |
|---|---|---|---|---|---|
| **R1** | ms-settings Open Command Registry Hijack | 47 (batch) | host (60 s) | S2 — EID 13 ValueSet under `HKCU\Software\Classes\ms-settings\Shell\Open\command` | Sigma `46dd5308`; MITRE DET0388 (registry half) |
| **C1** | Fodhelper Child Interpreter | 73 | host (30 s) | S2 — E1 interpreter with fodhelper parent | Sigma `7f741dcf`; MITRE DET0388 (process half) |
| **S1** | Script Host With Fodhelper or Cmd Parent | 47 | host (30 s) | S2 — wscript/cscript under fodhelper/cmd | Sigma `7f741dcf` family |
| **S2** | PowerShell Hidden and Bypass or Encoded Command Patterns | 47 | host+user (60 s) | S2/S4 — hidden + bypass/encoded flags | Sigma PowerShell flag corpus |
| **C2** | WMI Subscription Registration Sequence | 73 | host+computer (30 s) | S3 — EID 19/20/21 Created, ordered | Sigma `0f06a3a5`; MITRE DET0086/AN0236 |
| **R2** | WMI Consumer Activation After Notepad Trigger | 73 | host (60 s) | S4 — notepad E1 → WmiPrvSE-parented SYSTEM powershell (svhw.ps1) | MITRE DET0086/AN0236 (activation) |
| **S3** | SYSTEM Shell or Tool With WMI Host Parent | 73 | host (60 s) | S4 — shell/tool under WmiPrvSE/scrcons, SYSTEM | MITRE DET0086/AN0236; Sigma `sysmon_wmi_susp_scripting` |
| **C3** | WMI-Parented PowerShell Followed by Discovery Process | 73 | host (60 s) | S4/S5 — WMI-parented PS → discovery tool | MITRE DET0086/AN0236 + T1082/T1016 |
| **C4** | PowerShell Staging Files, ZIP Creation and Network Activity | 73 | host (120 s) | S5/S6 — staging file → zip → SYSTEM PS network | T1005/T1074.001/T1560.001 scenario shape |
| **S4** | SYSTEM PowerShell or Curl Network Activity on Web Ports | 73 | host (60 s) | S6 — E3 egress by SYSTEM ps/curl | generic web-port egress |
| **C5** | SYSTEM PowerShell Network Activity Followed by File Deletion | 73 | host (30 s) | S7 — SYSTEM PS E3 → EID 23 | T1070.004 deletion telemetry |

All rows are **signal-level building blocks** for the chain: no single row asserts a
confirmed incident; conclusion requires the ledger + verifier (per §3.1 taxonomy the
historical "Critical/High Fidelity" tags were replaced by `Signal` and the severities
normalised to medium/high, change recorded in CHANGELOG.md).

## Kill-chain mapping (stage → telemetry → rule)

| Stage | Victim-side artifacts | E# / key fields | Rule & what drives the match |
|---|---|---|---|
| **S2** UAC bypass | ms-settings hijack + fodhelper → wscript → elevated PS | EID 13 `TargetObject`, E1 parent fodhelper, E1 PS flags | R1 (registry), C1/S1 (fodhelper child), S2 (PS flags) |
| **S3** WMI install | consumer write `C:\Windows\Temp\svhw.ps1`; filter/consumer/binding | EID 11, EID 19/20/21 `Name`/`Operation` | C2 (ordered sequence; binding refs cross-checked by verifier) |
| **S4** Activation | notepad trigger → consumer under WmiPrvSE (SYSTEM) | E1 notepad; E1 PS parent=WmiPrvSE, `-f svhw.ps1` | R2 (sequence), S3 (context), C3 (discovery following) |
| **S5** Discovery/collection | arp, info.txt, staging copies, manifest | E1 arp; EID 11 paths/hashes | C3 (discovery), C4 stage 1 (staging creates) |
| **S6** Archive/exfil | wdmp.zip via curl to the internal sink; PS status message | EID 11 zip; E1/E3 curl; E3 PS; sink receipt | S4 (curl E3), C4 (status channel), receipt (transfer proof) |
| **S7** Cleanup | rd/del of staging + zip | EID 23 zip/staging paths | C5 |

## Run coverage

No verified run recorded at the time of writing. The historical April-2026 screenshots
are archived (not run evidence) under `evidence/sanitized-screenshots/`. The coverage
table becomes populated after the first verified run with the verifier's output per
rule (docs/detection-catalog detail was merged into this page).

## Rule-authoring notes

- EID 19/20/21 events have `event.category: wmi` — use `[any where ...]` in
  sequences; C2 uses `winlog.event_id` + `Operation`.
- EID 13 registry events: `TargetObject` is the key path; `Details` carries the
  value; `registry where` requires the registry event category.
- E3 timestamps can lag E1/E11 by seconds — order sequences by entity/time, not by
  E3 order alone; E3 is TCP/UDP only (no protocol/body proof).
- Alert volume from the 1 m schedule is bounded by the suppression groups above;
  counts in the alert index are upper bounds until dedup is confirmed per rule.
- Adding a rule requires BOTH the `.eql` file and a metadata block in
  `scripts/rules/gen_rules_ndjson.ps1` (an unloaded query imports silently and fails
  at execution with an empty query).

See `docs/correlation-architecture.md` for join keys and evidence tiers, and
`docs/attack-chain-plan.md` for per-stage boundaries.