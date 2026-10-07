# Operator runbook — WMI-LAB-1 (S1–S7)

Ground rules: use actual timestamps, record every retry and declare operator actions.
Runs 01–03 began at High integrity. [RUN-04](../../reports/reference-run-20261003-04.md)
records a filtered-administrator Medium-to-High transition using before/after
measurements and corroborating process context. Its attached reboot test is AV-off.
See the [validation guide](../../docs/validation/README.md) for assertion boundaries.

## Pre-run

1. Snapshot the victim VM.
2. Start the sink BOUND TO THE LAB INTERFACE with the lab token (shared credential;
   never commit it):
   ```
   $env:SINK_TOKEN='<lab token, >=16 chars, matches the guest runtime token>'
   python scripts/sink_server.py --bind 192.168.106.1 --port 9180
   ```
   The sink refuses 0.0.0.0 and refuses uploads without the token. Receipts are
   finalisable (`POST /receipt/<run_id>/finalise`) so a run's transfer evidence cannot
   be overwritten afterwards.
3. Stage the run-scoped payloads (the script refuses a sink outside 192.168.x.x):
   ```
   powershell scripts/prepare_run.ps1 -RunId <RUN-...> -SinkBase http://192.168.106.1:9180 `
       -HostName <guest> -SinkToken '<same token>'
   ```
   → writes `evidence/runs/<run_id>/payload/` and prints the staged consumer sha256
   (index it as ART-01-02; module integrity uses the GUEST PROBE, not an EID 11 hash).
4. Copy `evidence/runs/<run_id>/payload/` into the guest (e.g.
   `C:\Users\victim\Desktop\payloads\`).
5. Clock check: guest UTC aligned with the lab host; note the probe output.
6. `evidence/runs/<run_id>/` exists with the payload subfolder; schema unchanged.

## Stages (operator action → expected evidence → gate)

| Stage | Operator action | Expected evidence (ledger rows) | Gate before next |
|---|---|---|---|
| S1 | double-click `setup.bat` (victim session) | E1 `cmd.exe` | E1 seen |
| S2 | (automatic; assess starting integrity per run) | EID 13 `ms-settings` x2, E1 `fodhelper`, E1 `wscript` (parent fodhelper), E1 `powershell` (`-w hidden -ep bypass -f ...install.ps1`) | PowerShell E1 seen; elevation additionally requires recorded before/after integrity and corroborating process context |
| S3 | (automatic) | EID 11 `svhw.ps1`, EID 19/20/21 Created; read-back check `svhw.ps1` contains run id; **module integrity**: GUEST PROBE hash of `svhw.ps1` (recorded in `probe-svhw-hash.json`) == staged consumer hash (ART-01-02). The EID 11 event carries no Hash field; never write one from EID 11 | EID 21 seen; run id verified; probe hash matches |
| S4 | start `notepad.exe` | E1 `notepad.exe`, E1 `powershell` (parent `WmiPrvSE`, SYSTEM, `-f ...svhw.ps1`) | WmiPrvSE-parented PS E1 seen (SYSTEM context, not a UAC claim) |
| S5 | (automatic) | E1 `arp.exe` (SYSTEM), EID 11 `info.txt`, `_manifest.txt`, staging copies | manifest EID 11 seen |
| S6 | (automatic) | E1 `curl.exe`, E3 curl → sink port (entity-matched), E3 PowerShell status, sink receipt `ART-07-01-<run>.json` (verified against run/host/manifest) | receipt valid; consumer reported transfer_ok=true |
| S7 | (automatic) | E1 `cmd.exe` (SYSTEM), EID 23 `wdmp.zip` + staging files | EID 23 seen; post-cleanup probe clean |

Also see `scripts/reboot_survival_check.ps1` for the persistence-across-reboot
procedure. RUN-04 records an AV-off pass; an AV-on pass remains pending. State the
AV condition and observation times for each separate experiment.

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
  creds — labelled ACCEPTED-LEDGER-ONLY, never full ACCEPTED; full when
  `ES_URL`/`ES_USER`/`ES_PASS` are set).
- `python scripts/tests/test_offline.py` and
  `python tools/validate_repository.py` after any rule/payload change.

## Cleanup / recovery

- Kill any leftover consumer/tool processes; verify with a process list.
- Optionally remove the subscription (idempotent re-install path) or revert the VM
  snapshot; verify post-cleanup with the ART-08-01 probe.
- After a run's evidence is complete, finalise the sink receipt
  (`POST /receipt/<run_id>/finalise`) so the transfer record is immutable.
- Secrets: never paste credentials into ledgers, receipts, logs or exports. The
  SINK_TOKEN is a lab-only shared credential: it bounds attribution to "a token-holder
  on the lab network", never cryptographic attribution to the victim.
