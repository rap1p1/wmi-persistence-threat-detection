# Operator runbook — WMI-LAB-1 (S1–S7)

Ground rules (playbook 2.3/2.4/§E): real timestamps only; a step may run only after
its gate is proven; every retry is recorded as a separate evidence row; operator
actions are declared as such here.

## Pre-run

1. Snapshot the victim VM.
2. Start the sink: `python scripts/sink_server.py --port 9180`
   (receipt dir defaults to `evidence/runs/`).
3. Stage the run-scoped payloads:
   `powershell scripts/prepare_run.ps1 -RunId <RUN-...> -SinkBase http://<lab-host>:9180
   -HostName <guest>` → writes `evidence/runs/<run_id>/payload/` and prints the staged
   consumer sha256 (index it as ART-01-02 in the ledger).
4. Copy `evidence/runs/<run_id>/payload/` into the guest (e.g.
   `C:\Users\victim\Desktop\payloads\`).
5. Clock check: guest UTC aligned with the lab host; note the probe output.
6. `evidence/runs/<run_id>/` exists with the payload subfolder; schema unchanged.

## Stages (operator action → expected evidence → gate)

| Stage | Operator action | Expected evidence (ledger rows) | Gate before next |
|---|---|---|---|
| S1 | double-click `setup.bat` (victim session) | E1 `cmd.exe` | E1 seen |
| S2 | (automatic) | EID 13 `ms-settings` x2, E1 `fodhelper`, E1 `wscript` (parent fodhelper), E1 `powershell` (`-w hidden -ep bypass -f ...install.ps1`) | elevated PowerShell E1 seen |
| S3 | (automatic) | EID 11 `svhw.ps1` (record the `Hash` field as `file_hash` on the row), EID 19/20/21 Created; read-back check `svhw.ps1` contains run id; **module integrity**: EID 11 hash == staged consumer hash (ART-01-02) | EID 21 seen; run id verified; module hash matches |
| S4 | start `notepad.exe` | E1 `notepad.exe`, E1 `powershell` (parent `WmiPrvSE`, SYSTEM, `-f ...svhw.ps1`) | WmiPrvSE-parented PS E1 seen |
| S5 | (automatic) | E1 `arp.exe` (SYSTEM), EID 11 `info.txt`, `_manifest.txt`, staging copies | manifest EID 11 seen |
| S6 | (automatic) | E1 `curl.exe`, E3 curl → sink port, E3 PowerShell status, sink receipt `ART-07-01-<run>.json` | receipt exists and valid |
| S7 | (automatic) | E1 `cmd.exe` (SYSTEM), EID 23 `wdmp.zip` + staging files | EID 23 seen; post-cleanup probe clean |

## Evidence capture (after the run)

For each stage run `scripts/verify/fetch_evidence_ids.py --index sysmon
--event-code <n> --filter '...' --window <start>,<end>` and copy the returned
`_id`/`@timestamp` rows into the ledger `evidence_refs` (kind `event`). Do not
invent values; a stage with no captured events is `SENSOR GAP`, not PASS.

Examples:

```
set ES_URL=https://<elastic>:9200 & set ES_PASS=... &
python scripts/verify/fetch_evidence_ids.py --index sysmon --event-code 13 ^
    --filter 'winlog.event_data.TargetObject:"ms-settings"' --window <start>,<end>
python scripts/verify/fetch_evidence_ids.py --index sysmon --event-code 21 ^
    --filter 'winlog.event_data.Operation:"Created"' --window <start>,<end>
```

## Verification

- `python scripts/verify/verify_run_evidence.py <run_id>` (ledger-only without ES
  creds; full when `ES_URL`/`ES_USER`/`ES_PASS` are set).
- `python scripts/tests/test_offline.py` and
  `python tools/validate_repository.py` after any rule/payload change.

## Cleanup / recovery

- Kill any leftover consumer/tool processes; verify with a process list.
- Optionally remove the subscription (idempotent re-install path) or revert the VM
  snapshot; verify post-cleanup with the ART-08-01 probe.
- Secrets: never paste credentials into ledgers, receipts, logs or exports.