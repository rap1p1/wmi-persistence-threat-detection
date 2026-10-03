# Correlation Architecture — WMI Lab

> Defines how telemetry is joined into an evidenced chain for the WMI persistence +
> UAC bypass kill chain. It separates three layers: **event-level correlation**
> (joining events of the same activity), **phase-level handoff** (the output of one
> stage being consumed by the next, see `attack-chain-plan.md`), and
> **orchestration / run ledger** (ground truth, never endpoint telemetry).
>
> Primary rule: **never elevate a conclusion just because several events are close in
> time.** If `process.entity_id` is empty, references do not match, timestamps skew, or
> E3 lacks process attribution, downgrade the tier and record the reason.

## 1. Correlation dimensions

| Dimension | Keys / fields | Rules |
|---|---|---|
| `run_id` | `RUN-YYYYMMDD-<seq>` / `WMI-LAB-1` | Telemetry never carries run_id (no standard field); run_id lives in the run ledger (`evidence/runs/RUN-<id>/RUN-<id>.json`) and in artifacts. Correlation attributes a run back to run_id using window + host + account, then cross-checks the ledger. |
| Host / account | `host.name`, `user.name` / `user.id` (SID) | Process joins are **same-host only**. `user.name` joins support same-user aggregation only; `SYSTEM` must match `NT AUTHORITY\SYSTEM` with the agent's exact mapping. |
| Process | `process.entity_id` (ProcessGuid), `process.parent.entity_id`, `process.pid` + host + time | `process.entity_id` is the join key for E1 -> E1 -> E11 -> E3 **within the same host**. Never join PIDs across hosts or runs; never decode the ProcessGuid suffix as a PID. Empty entity (`00000000-...`) means no process-level join. |
| WMI objects | EID 19/20/21; `Name`, `Operation`, `Consumer`, `Filter` | Registration (19/20/21) ≠ binding-valid ≠ activation ≠ survival across reboot. The **binding reference** is carried by EID 21 `Consumer` / `Filter` fields; see §2. C2. |
| Files | `file.path`, `file.extension`, `file.hash.sha256`, producer process | EID 11 = create/overwrite, not normal reads. A path-scoped create in `\Windows\Temp\` does not prove collection of source documents. Cross-host/key: sink receipt hash ⇄ in-guest manifest hash (§2. Transfer). |
| Network | `destination.ip`, `destination.port`, process entity | E3 covers TCP/UDP connections only: no HTTP body, URL path, byte count, JA3/JA4 or TLS certificate; it cannot confirm a file transfer completed. E3 attribution must resolve to an E1 entity on the same host. |
| Time | `@timestamp` (UTC), `event.ingested` | Budget clock skew across hosts (align clocks before a run). Distinguish event time from ingest time. Windows must be measured from real events; placeholders are forbidden (§2.3 of the playbook). |
| Orchestration | stage id, input/output artifact, status, evidence_links | Ground truth only; never a substitute for endpoint telemetry. |

## 2. Join keys per detection

### C2 / R2 — WMI subscription registration and activation

- **Registration join (C2):** ordered EID 19 → 20 → 21 with `Operation=Created` on the
  same host within 30 s. Name-based exclusions were **removed** (object names do not
  prove provenance). EQL sequences join **only by keys** — the query cannot bind a
  value from one event into another, so the *binding-reference* join is executed by
  the **acceptance verifier** over the ledger's stored WMI fields: EID 21 `Consumer`
  text must contain the EID 20 `Name` and EID 21 `Filter` text the EID 19 `Name`
  (verified for RUN-20261003-01: `SystemDumpConsumer` / `NotepadFilter`).
- **Activation join (R2):** generalized — any WMI subscription registration
  (19/20/21 Created) followed within 10 m by a WMI-hosted interpreter (parent
  WmiPrvSE/scrcons) on the same host. No trigger binary or lab script name is
  required. Host/time correlation (TEMPORAL); the consumer's parent identity
  (parent.entity_id) and its child tail (ARP/curl/cmd) are verifier-checked.

### C1 / R1 / S1 — UAC bypass (fodhelper + ms-settings registry hijack)

- **Process link (direct, verifier-checked):** E1 `wscript.exe` →
  `fodhelper.exe` + E1 `powershell` → wscript — by `parent.entity_id`.
- **Registry stage (R1):** EID 13 with `registry.path` matching
  `ms-settings\Shell\Open\command` and value `(Default)`/`DelegateExecute`
  (ECS `registry.path`/`registry.value` verified on the lab stack; case-insensitive;
  no SID dependency).
- **Registry → fodhelper link:** `TEMPORAL/CONTEXTUAL ONLY`.
- Elevated token is asserted only if the S4 consumer runs as SYSTEM; the S2 mechanism
  alone (here: an operator-launched High-integrity session) does not prove a
  Medium→High privilege transition.

### C4 — single-entity staging → archive

- EID 11 file creates **joined by `process.entity_id`** (verified populated on this
  stack; EID 11 does NOT carry `process.parent` here): a non-archive create followed
  by a zip create by the same entity within 2 m. No lab folder/file names required.
- Staging creates (incl. generated manifests) do not prove collection; archive
  creation does not prove contents or transfer.

### S4 — curl upload-intent + connection

- E1 `curl.exe` whose command line carries upload intent (`-T`, `--upload-file`,
  `-F`/`--form`, `--data-binary`, `-d`) followed by an E3 owned by that **same curl
  entity** (verifier-checked; RUN-20261003-01: E3 entity == E1 entity).
- No port/IP allow/deny lists; "intent + connection", never transfer success.

### C5 — archive created then deleted

- EID 11 (zip) → EID 23 (zip) on the same host within 2 m; the **same-file-path**
  equality is verifier-checked from the ledger fields (RUN-20261003-01:
  `C:\Windows\Temp\wdmp.zip` created 09:55:34.975, deleted 09:55:39.180). No archive
  name hard-coded; deletion does not imply transfer success.

### Transfer integrity (S6) — the strongest link

- In-guest manifest snapshot `ART-06-01` (text, canonical hash = sha256 over
  CRLF→LF normalized bytes) records the staged file set + the pre-send zip sha256.
- Sink receipt `ART-07-01` (server-side, written by `scripts/sink_server.py`)
  records the received file name, raw-byte size and sha256, plus the canonical
  manifest hash echoed from the client.
- Equality assertions (verifier): receipt `sha256` (raw bytes, zip is binary) ==
  guest-computed zip sha256; receipt non-empty; captured manifest canonical hash ==
  the hash recorded in the receipt.
- Cross-host hash is the join key between producer (guest) and consumer (sink).

### Module integrity (S3) — byte-identical staged consumer

- `scripts/prepare_run.ps1` writes the run-scoped staged copy under
  `evidence/runs/<run_id>/payload/` (indexed as `ART-01-02`) and prints its raw
  sha256. `install.ps1` materializes `svhw.ps1` with byte-fidelity (no BOM, no
  line-ending conversion), so the guest file is byte-identical to the staged copy.
- Join (verifier): the RECORDED `svhw.ps1` hash equals the raw sha256 of the staged
  consumer — a DIRECT EVENT LINK (hash equality across hosts, §1.4 Module integrity).
  On this stack the EID 11 event does not populate Hashes, so the guest-side value is
  captured by probe and its provenance is carried in the ledger ref
  (`file_hash_provenance`) — it is labelled as such, never as an event field.
- The received archive is evidenced by the sink receipt (name/size/sha256); the
  archive bytes are `*.zip`-gitignored and not indexed as an artifact (the receipt is
  the server-side ground truth). Text artifacts are indexed canonically; the module
  join uses the raw hash because Sysmon hashes raw bytes.

> **EQL join scope (verified on the lab stack, ES 9.5.3):** `sequence by` accepts one
> field list shared by every step — asymmetric joins (step1.process.entity_id ==
> step2.process.parent.entity_id, E1↔E3 ownership, create/delete same file.path) are
> NOT expressible in EQL. The queries stay host/time correlations and the assertions
> are executed by the acceptance verifier (`join_checks`).

## 3. Correlation tiers

| Tier | Meaning | Valid example |
|---|---|---|
| `DIRECT EVENT LINK` | Same trustworthy technical key in telemetry | fodhelper E1 -> wscript E1 by `parent.entity_id` |
| `SUPPORTED PHASE HANDOFF` | Artifact/state produced by stage A, consumed by B, with producer/consumer evidence + run id | `ART-06-01` manifest -> `ART-07-01` sink receipt (hash equality) |
| `TEMPORAL/CONTEXTUAL ONLY` | Same time/host/context, causality not proven | registry EID 13 -> fodhelper E1; WMI subscription -> WmiPrvSE child |
| `UNPROVEN` | Evidence missing or inconclusive | "persistence survived reboot" without a controlled reboot |
| `CONTRADICTED` | Evidence conflicts | PID reused across two events on the same host, read as identity |

**Downgrade triggers (apply, record reason):** empty `process.entity_id`; EID 21
references not matching 19/20 names or raw format unvalidated; E3 without an owning E1
entity; timestamp skew beyond the clock budget; a name/path marker colliding across
runs; any count-based ("N alerts") claim without per-event reconciliation.

## 4. Boundaries declared by design (mirrors playbook §D/§F)

- EID 11 staging creates do not prove source-file collection; only the manifest +
  receipt prove what left the host.
- A connection event (E3) does not prove transfer; only the sink receipt does.
- Registration (C2) does not prove activation (R2) or reboot survival (untested
  until a controlled reboot stage is added).
- The consumer runs as SYSTEM only if the activation evidence shows a
  `WmiPrvSE`-parented `powershell`; absent that, the S2→S3 "elevation" story is
  unproven.
- History clearing (`Clear-Content`) produces no Sysmon delete event; it is declared
  out of the evidence set, not silently credited.
- Operator actions (double-click of `setup.bat`, launching `notepad.exe`) have a
  parent the agent chain never shows; they are declared as operator actions in the
  runbook so the chain stays honest.

## 5. Rule / correlation index

| Corr | Stage | Input signals | Join keys / window | Expected tier | Status |
|---|---|---|---|---|---|
| R1 | S2 | EID 13 `registry.path` ms-settings + value | host + key signature | TEMPORAL/CONTEXTUAL (single event) | verified (RUN-20261003-01: 2) |
| C1/S1 | S2 | EID 1 fodhelper -> interpreter | `parent.entity_id` (verifier) | DIRECT | verified (1) |
| S2 | S2/S4 | EID 1 PS flags (hidden+bypass or encoded) | single event; no parent-name exclusions | building block | verified (2, incl. consumer) |
| C2 | S3 | EID 19/20/21 | host + order + 30 s; binding refs verifier-checked | TEMPORAL/CONTEXTUAL + binding check | verified (1) |
| R2 | S3/S4 | EID 19/20/21 -> WmiPrvSE interpreter | host + 10 m (no lab names) | TEMPORAL/CONTEXTUAL | verified (1) |
| S3 | S4 | EID 1 parent WmiPrvSE/scrcons SYSTEM | single event | building block | verified (1) |
| C3 | S4/S5 | WMI-hosted interpreter -> discovery | host + 30 s; ancestry verifier-checked | TEMPORAL/CONTEXTUAL + verifier join | verified (1) |
| C4 | S5/S6 | EID 11 non-archive -> zip (same entity) | `process.entity_id` | DIRECT (entity) | verified (1) |
| S4 | S6 | curl upload-intent E1 -> E3 | `process.entity_id` | DIRECT (entity) | verified (1) |
| C5 | S7 | EID 11 zip -> EID 23 zip | host + 2 m; same-path verifier-checked | TEMPORAL/CONTEXTUAL + verifier join | verified (1) |
| Transfer | S6 | manifest ⇄ receipt | canonical/raw sha256 + size + name | SUPPORTED PHASE HANDOFF | verified (ACCEPTED) |

## 6. Sensor / ingest checklist (before validating any correlation)

Track each item in three states — CONFIGURED, LOCAL OBSERVED, INGEST VERIFIED — and
validate a correlation only when its dependencies are INGEST VERIFIED (per-run probe
queries, one event each; agent Healthy alone proves nothing §1.1).

1. EID 1: non-empty `process.entity_id` + `parent.entity_id` on the victim host.
2. EID 3: record attribution status (process name + entity resolved from E1).
3. EID 11 / 23: `file.path`, `file.extension`, user, process resolution.
4. EID 12/13/14 registry events: `TargetObject` / `Details` mapping; `ms-settings` key
   captured before `setup.bat` deletes it (write/delete happen ~3 s apart; schedule
   window covers it).
5. EID 19/20/21: confirm the Sysmon `<WmiEvent onmatch="exclude">` empty block does
   not suppress WMI events (prove one local WMI event reaches the channel); capture
   EID 21 `Consumer` / `Filter` raw layout for the reference parse.
6. Hash fields: `file.hash.sha256` / `Hashes` present for scripts and the archive.
7. Clock: victim host UTC + aligned with the lab host (one `w32tm /stripchart` or
   equivalent artifact per run).
8. Ingest parity: for each channel, at least one local event found in Elastic by
   host, channel, RecordID and time; check E255 / ingest errors during the run.

References: `attack-chain-plan.md` (stage design), `detections/README.md` (rule
index), `evidence/runs/RUN-schema.json` (ledger), verifier
`scripts/verify/verify_run_evidence.py`.