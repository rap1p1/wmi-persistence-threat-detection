# Reference Run Report — RUN-20261003-01

Window: 2026-10-03 09:54:43Z – 09:56:30Z. Ledger + artifacts:
`evidence/runs/RUN-20261003-01/`. Verifier:
`scripts/verify/verify_run_evidence.py RUN-20261003-01` → **ACCEPTED**.

## 1. Context / scope

Personal-host lab (workgroup, no AD): victim VM `WMI` (hostname `wmi`, Windows 10 Pro
19045.3803, local account `Duc` in Administrators — the filtered-token story is the
scenario premise; see limitations). Elasticsearch 9.5.3 (lab stack), Sysmon 15.21 with
this repository's config (explicit log-all Network/Registry/WMI sections), Elastic
Agent shipping Sysmon + Security channels, internal sink on the repo host
(`192.168.106.1:9180`). Scenario: normal user context runs `setup.bat` → fodhelper
UAC-bypass mechanism → WMI event subscription → notepad activation → discovery/
collection/archive → exfil to the internal sink → cleanup. The chain was
**operator-launched via vmrun** (declared operator action, session 0, High integrity
token — see limitations).

## 2. Timeline (real event times)

| Time (Z) | Observation |
|---|---|
| 09:54:45.815 | S1 — `cmd.exe` runs `setup.bat` (E1) |
| 09:54:45.887 | S2 — registry value set `HKU\S-..._Classes\ms-settings\Shell\Open\command\(Default)` → `wscript.exe "…\r.vbs"` (EID 13) |
| 09:54:45.887 | S2 — registry value set `…\command\DelegateExecute` → `(Empty)` (EID 13) |
| 09:54:45.900 | S2 — `fodhelper.exe` (parent cmd) |
| 09:54:46.119 | S2 — `wscript.exe` (parent fodhelper) |
| 09:54:46.190 | S2 — elevated `powershell -WindowStyle Hidden -ExecutionPolicy Bypass -File …\install.ps1` |
| 09:54:47.466 | S3 — `svhw.ps1` written to `C:\Windows\Temp` (EID 11) |
| 09:54:48.120 | S3 — EID 19 `NotepadFilter` Created |
| 09:54:48.137 | S3 — EID 20 `SystemDumpConsumer` Created |
| 09:54:48.168 | S3 — EID 21 binding Created |
| 09:55:28.319 | S4 — `notepad.exe` launch (trigger) |
| 09:55:33.249 | S4 — consumer `powershell` under `WmiPrvSE.exe`, SYSTEM, `-f …\svhw.ps1` |
| 09:55:33.7–34.7 | S5 — staging writes under `C:\Windows\Temp\wdmp\` (EID 11; `info.txt`, copies) |
| 09:55:34.704 | S5 — `ARP.EXE -a` (SYSTEM) |
| 09:55:35.194/244 | S6 — `curl.exe` PUT archive / manifest to the sink |
| 09:55:36.797 | S6 — curl E3 → `192.168.106.1:9180` |
| 09:55:36.802 | S6 — PowerShell status E3 (status channel) |
| 09:55:39.180 | S7 — `wdmp.zip` deletion (EID 23) |

## 3. Per-stage evidence table

| Stage | Status | Evidence (event code → es_id / ts) | Boundary / note |
|---|---|---|---|
| S1 | PASS | E1 `AaEBMN8OoLLJxo4Fkbwr` 09:54:45.815 | operator action (vmrun), declared |
| S2 | PASS | EID13 `…FkbxH/L` 09:54:45.887; E1 fodhelper `…FkbxN` 09:54:45.900; wscript `…Fkby8` 09:54:46.119; PS `…FkrwV` 09:54:46.190 | registry→fodhelper TEMPORAL/CONTEXTUAL; ancestry fodhelper→wscript→ps verifier-checked via parent.entity_id |
| S3 | PASS | EID11 `…Ok4eC` 09:54:47.466 (file_hash `6B90E6F8…`); EID19 `…OlomC`; EID20 `…OlomI`; EID21 `…Oloma` 09:54:48.1 | module integrity: recorded svhw.ps1 hash (guest probe 09:56Z — the EID11 doc carries no Hashes on this stack) == staged consumer `ART-01-02`; binding refs verifier-checked: filter→NotepadFilter, consumer→SystemDumpConsumer |
| S4 | PASS | E1 notepad `…t5RwS` 09:55:28.319; E1 WmiPrvSE→ps `…69_N8k` 09:55:33.249 | activation; consumer as SYSTEM (parent entity = WmiPrvSE identity) |
| S5 | PASS | E1 ARP `…OEQdW` 09:55:34.704; EID11 `info.txt`/`_manifest.txt` | in-process queries not independently evidenced; ARP parent entity == consumer entity (verifier) |
| S6 | PASS | E11 zip `…OFAgY` 09:55:34.975; E1 curl `…OFAid/OFAju`; E3 curl `…MDTG7` 09:55:36.797; E3 PS `…MDzFL` 09:55:36.802; receipt `ART-07-01` | archive create by consumer entity; curl E1↔E3 entity-owned (S4); PS status channel is NOT the transfer (receipt proves transfer) |
| S7 | PASS | EID23 `…bHnHx` 09:55:39.180 | wdmp.zip deletion; create/delete same `file_path` (verifier); `Clear-Content` history not event-evidenced |

Artifacts: `ART-01-01/02/03` staged payloads (canonical hashes, `ART-01-02` raw =
module anchor); `ART-06-01` manifest snapshot (canonical `51D3B6AE…` == receipt
`manifest_sha256`); `ART-07-01` sink receipt (name/size/sha256 of the received
archive — the transfer evidence; the archive itself is `*.zip`-gitignored and not
indexed as an artifact); `ART-08-01` cleanup verification (guest probe).

## 4. Detection volume split (direct EQL re-evaluation over the run window)

Method: each exported rule's query re-run via Elasticsearch `_eql/search` over the run
window (rules carry `building_block_type=default`; no stored alerts yet in this first
verification — this is an equivalent, reproducible query-level evaluation). Rewritten
per the review round: deployment-agnostic WMI correlation (R2), curl upload-intent +
entity-owned connection (S4), single-entity staging→archive (C4), archive create→
delete (C5), ancestry/binding/path joins at the verifier.

| Rule | Matches | Notes |
|---|---|---|
| R1 ms-settings Open Command Registry Hijack | 2 | both EID 13 writes (Default + DelegateExecute/empty), `registry.path` mapping verified |
| C1 Fodhelper Child Interpreter | 1 | wscript under fodhelper |
| S1 Script Host w/ Fodhelper/Cmd Parent | 1 | same event as C1 (overlap documented, not independent) |
| S2 PowerShell Hidden and Bypass or Encoded | 2 | install.ps1 PS + consumer PS (both hidden+bypass; consumer also matches S3/R2 — one event, several signals, documented) |
| C2 WMI Subscription Registration Sequence | 1 | 19→20→21; binding refs verifier-checked (NotepadFilter/SystemDumpConsumer) |
| R2 WMI Subscription Registration → WMI-Hosted Interpreter | 1 | registration → consumer under WmiPrvSE (host/time; maxspan 10 m, no lab names) |
| S3 SYSTEM Shell/Tool w/ WMI Host Parent | 1 | consumer powershell |
| C3 WMI-Hosted Interpreter → Discovery | 1 | interpreter → ARP.EXE (host/time; ancestry verified by the verifier via parent entity) |
| C4 Staging and Archive Creation by a Single Process | 1 | consumer entity: staging create → zip create (EID 11 x2, same entity) |
| S4 Curl Upload-Intent Process Making a Connection | 1 | curl with `-T`/`--data-binary` then E3 owned by the same entity |
| C5 Archive Creation Followed by Archive Deletion | 1 | wdmp.zip create (09:55:34.975) + delete (09:55:39.180); same path (verifier) |

Negative control window (2026-10-03 10:00–10:05Z, idle): **0 matches for all 11 rules**.

Live-alert smoke (separate from this run, after import): a registry `ms-settings`
write+delete in the guest (2026-10-03 10:36:39Z) produced 2 EID 13 events; **R1
stored 2 alerts at 10:37:16Z** via the scheduled evaluation; the other 10 rules
stored 0. This run's window predates the Kibana import, so the table above remains
query-level re-evaluation; the smoke confirms the import → schedule → alert pipeline.

## 4b. EQL join limitation (recorded, not asserted away)

Tested on the lab stack (ES 9.5.3): `sequence by` accepts one field list shared by
ALL steps — it cannot map step1.process.entity_id onto step2.process.parent.entity_id.
The C3 (interpreter→discovery ancestry), S4 (E1↔E3 ownership) and C5 (archive
create/delete same path) assertions are therefore enforced by the acceptance verifier
over the ledger's stored fields; the queries remain host/time correlations and the
report says so. (`scripts/verify/verify_run_evidence.py` join_checks.)

## 5. Limitations (honest)

- **Operator-launched, High-integrity session**: vmrun/Tools processes run in session 0
  with a High-integrity token (`Mandatory Label\High Mandatory Level`). The S2 UAC
  bypass therefore replayed its mechanism (registry → fodhelper → script host) rather
  than demonstrating a privilege gain; "elevation succeeded" is only supported by S4's
  SYSTEM consumer. Fidelity note documented in `docs/attack-chain-plan.md` limitations.
- **Rule evaluation**: direct EQL re-evaluation, not stored alerts (rules imported
  after this run; the next run will produce live alerts). Kibana import + execution
  status to be recorded in a follow-up run.
- **EID 11 `svhw.ps1` carried no Hashes** on this stack → module integrity evidenced
  via a guest probe (09:56Z) instead of the event field; equal to the staged hash.
- **C2 binding references**: EID 21 `Consumer`/`Filter` text was cross-checked against
  EID 19/20 names at the event level (analyst/verifier check; EQL cannot bind values).
- **w32tm service disabled** on the guest; clocks were aligned within ~4 s (tolerance
  used by the verifier is 5 s). Event time vs ingest time distinguished in the ledger.
- **No reboot-survival test**; subscription activation only (R2). WMI-Activity channel
  not enabled → subscription→execution attribution is TEMPORAL/CONTEXTUAL beyond the
  process-entity link.
- **S5 in-process queries** (Get-CimInstance/Get-NetIPAddress/Get-LocalUser) are not
  independently event-evidenced (only `info.txt` + ARP); declared, not compensated.
- **Vendor rule ids** (Elastic/Splunk) remain name-referenced; pinned ids pending
  those packs.
- Registry writes are short-lived (key deleted ~3 s later) — detection within the
  schedule window is assumed, not measured for latency.

## 6. Recovery / cleanup

- Snapshot `before-run-20261003-01` exists (rollback point). The WMI subscription was
  left installed by design (persistence story); recovery = remove via elevated WMI
  delete or revert the snapshot.
- Sink stopped after evidence collection; ES credentials were environment-only.
- Guest post-run state verified: `wdmp.zip`/`wdmp` removed, `svhw.ps1` present,
  subscription present (`ART-08-01`).

## 7. References

- Ledger + artifacts: `evidence/runs/RUN-20261003-01/`
- Rule index + detection basis: `detections/README.md`
- Correlation/joins: `docs/correlation-architecture.md` · Chain: `docs/attack-chain-plan.md`
- Verifier: `scripts/verify/verify_run_evidence.py` (ACCEPTED incl. ES re-verification, 21 events)
- Build helper: `scripts/build_ledger_run01.py`