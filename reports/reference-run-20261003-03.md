# Reference Run Report — RUN-20261003-03 (final export)

Window: **2026-10-03T11:36:20Z – 11:40:00Z** (declared run window). Ledger:
`evidence/runs/RUN-20261003-03/` — stage statuses are **OBSERVED** (the builder does
not self-certify); acceptance is the verifier's grading.

Verifier:
`python scripts/verify/verify_run_evidence.py RUN-20261003-03` → **ACCEPTED (ES-BACKED)**
(22 event refs across 22 unique documents re-fetched; timestamp, event code, host,
channel and join/destination fields matched).

Evidence counts (machine-recordable, from the ledger `builder` block):
**22 event refs / 22 unique `_id`** (no duplicates); **38 collector E3s** are held in
`baseline_telemetry` and are NOT campaign refs.

## 1. Context / scope

Personal-host lab, victim `wmi` (Win10 19045). The chain is **operator-launched via
vmrun** from a High-integrity session — the fodhelper mechanism is replayed, not a
demonstrated Medium→High UAC transition (see limitations). Rules live in Kibana: the
**11-rule export** (including the E1-only S4). Key changes vs earlier runs: the ledger
is built inside an explicit finite window with every ref inside it, and E3 ownership is
joined by `process.entity_id`.

Provenance is recorded in the ledger (`provenance`): repo commit at capture time,
`config/sysmon-config.xml` sha256, rule-export sha256, observed Elasticsearch 9.5.3,
guest-observed Sysmon 15.21 / Elastic Agent 9.5.3, sink receipt file + sha256.
Historical gaps are labelled "not captured"; the recorded commit is the capture-time
HEAD, not a session-immutable run commit.

## 2. Timeline (real event times from the ledger)

| Time (Z) | Stage | Observation |
|---|---|---|
| 11:36:25.881 | S1 | `cmd.exe` runs `setup.bat` (operator action) |
| 11:36:25.933 / .947 / .955 | S2 | `reg.exe` delete/add/add on `ms-settings\Shell\Open\command` (EID 13) |
| 11:36:25.963 | S2 | `fodhelper.exe` (parent cmd) |
| 11:36:25.965 | S2 | `timeout.exe` (launcher wait) |
| 11:36:26.xxx | S2 | `wscript.exe` → `powershell.exe` (`-f install.ps1`) |
| 11:36:27.7xx | S3 | `svhw.ps1` write (EID 11) |
| 11:36:27.732 / .744 / .769 | S3 | EID 19 / 20 / 21 Created (`NotepadFilter`, `SystemDumpConsumer`, binding) |
| 11:36:44.396 | S4 | `notepad.exe` trigger |
| 11:36:47.853 | S4 | consumer `powershell` (parent **WmiPrvSE.exe**, user **SYSTEM**) |
| 11:36:4x | S5 | `ARP.EXE`, `info.txt`, `_manifest.txt` |
| 11:36:4x | S6 | `wdmp.zip` create; curl E1 ×2; curl E3 ×2 → `192.168.106.1:9180`; PS status E3 |
| 11:36:4x | S7 | `wdmp.zip` deletion (same path as creation) |

Rows marked `11:36:4x` are **minute-precision approximations** (the exact values are in
the ledger refs, which are the authoritative source); every other row is an exact
ledger timestamp.

## 3. Per-stage evidence (verifier-graded)

| Stage | Status | Verified assertions |
|---|---|---|
| S1 | PASS | entry E1 present with process identity |
| S2 | PASS | EID 13 registry path recorded; ancestry `fodhelper→wscript→powershell` by `parent.entity_id` |
| S3 | PASS | EID 19/20/21 Created; binding references parsed and equal (`__EventFilter.Name="NotepadFilter"`, `CommandLineEventConsumer.Name="SystemDumpConsumer"`), ordered inside the window; module hash == staged consumer (canonical) |
| S4 | PASS | consumer user **SYSTEM**, parent name **WmiPrvSE.exe**, consumer after the notepad trigger |
| S5 | PASS | ARP.EXE present; its `parent.entity_id` == consumer entity |
| S6 | PASS | archive create by consumer entity; **each** curl E1 matched to an E3 by entity, destination `192.168.106.1:9180`, after the E1; PS status E3 owned by the consumer; receipt bound to run/host/manifest |
| S7 | PASS | deletion of the same `file.path` created in S6; cleanup artifact parsed, run-bound, all checks PASS |

Transfer evidence: the sink receipt (`ART-07-01-RUN-20261003-03.json`) records
`wdmp.zip` size 14661 and its sha256; the local archive bytes (gitignored, present in
the private environment) match that receipt. **The committed transfer evidence is the
receipt** — a fresh clone cannot re-verify archive bytes.

## 4. Detection results — stored alerts (exported manifest)

`evidence/runs/RUN-20261003-03/alert-manifest.json` carries every stored alert with its
`_id`, rule id/name, alert timestamp, original time/event code/action, depth and
ancestor ids — so the counts are independently checkable.

| Rule | Stored alerts |
|---|---|
| R1 | 2 |
| C1 | 1 |
| S1 | 1 |
| S2 | 2 |
| C2 | 4 |
| R2 | 3 |
| S3 | 1 |
| C3 | 3 |
| C4 | 3 |
| S4 | 2 |
| C5 | 3 |
| **Total** | **25** |

Semantics: **25 stored alerts ≠ 25 behaviours**. With a 1-minute schedule and 2-minute
look-back, one event cluster is re-evaluated and re-alerted across consecutive rule
runs; suppression bounds within-run merging only. The manifest exposes alert
`@timestamp` and `original_time`, so re-matching is inspectable rather than assumed.
Direct EQL re-evaluation of the same window yields one cluster per rule (R1 and S2
two) — that is the behaviour count; stored alerts are the upper bound.

Control window (2026-10-03 10:00–10:05Z, idle, **5 minutes**): 0 matches for all 11
rules. This is a short negative check only — **not** a false-positive rate, precision,
or accuracy measurement. A longer baseline is required before any performance claim.

## 5. Limitations (honest)

- **Operator-launched High-integrity session**: the UAC bypass mechanism is replayed;
  a Medium→High transition is not demonstrated (S4's SYSTEM consumer is the
  elevation-path evidence).
- **No reboot-survival test**: the subscription is left installed by design.
- **In-process discovery** (Get-CimInstance/Get-NetIPAddress/Get-LocalUser) is not
  independently event-evidenced; only `ARP.EXE` and the manifest/staging writes are.
- **Sysmon E3 for the short-lived curl carries `Image: <unknown process>`**
  (process.name empty) while the entity is correct; ownership is therefore proven by
  `process.entity_id` and the name-less condition is annotated, not treated as a
  failure.
- **Receipt ≠ archive bytes**: the committed evidence is the sink receipt; the archive
  bytes are only verifiable where the archive exists (private environment).
- **Alert counts** are upper bounds (schedule/lookback re-matching); see §4.
- Cleanup claims are bounded by what the events show (no history-clearing evidence;
  `Clear-Content` produces no Sysmon delete event).

## 6. Recovery / cleanup

Snapshot `before-run-20261003-03` exists. Guest post-run probe: `wdmp.zip`/`wdmp`
removed, `svhw.ps1` present (run id inside), subscription re-installed by design —
recorded in `ART-08-01-RUN-20261003-03.json` (parsed by the verifier: all checks PASS,
run-bound). Subscription teardown is a manual recovery step; reboot survival untested.

## 7. References

- Ledger + artifacts: `evidence/runs/RUN-20261003-03/`
- Alert manifest: `evidence/runs/RUN-20261003-03/alert-manifest.json`
- Rules + detection basis: `detections/README.md` · joins: `docs/correlation-architecture.md`
- Chain: `docs/attack-chain-plan.md` · verifier: `scripts/verify/verify_run_evidence.py`
- Builder: `scripts/build_ledger_run.py` · provenance: `scripts/capture_provenance.py`