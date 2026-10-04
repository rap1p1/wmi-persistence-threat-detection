# Change record

## 2026-10-04 - RUN-20261003-04 (Medium-integrity start) + reboot survival + sink/elevation hardening exercised

- **Medium-integrity run executed (the elevation test).** The chain was launched from
  the filtered token of local Administrator `wmi\duc` (LIMITED scheduled task): the
  S2 elevation gate now records `ok S2 elevation: Medium (S-1-16-8192) -> High
  (S-1-16-12288) (Medium->High observed)` from elevation-before/after measurements,
  corroborated by per-event Sysmon E1 `IntegrityLevel` (cmd/reg Medium; fodhelper
  Medium->High trampoline; wscript/powershell High; consumer/curl System). The UAC
  bypass mechanism's filtered-token transition is now EVIDENCED, not assumed.
- **Reboot survival (AV-off) executed.** Guest power-cycled; subscription objects
  (filter/consumer/binding) survived and the post-boot notepad trigger fired the
  consumer (E1 AaEGEjMycFpEpRZGWiM- 2026-10-04T08:40:21Z, parent WmiPrvSE, SYSTEM,
  integrity System). Windows Defender was STOPPED in the guest - the AV-on pass
  remains pending (identical procedure, documented). No persistence-vs-AV claim.
- **Sink contract exercised live:** bound interface, token auth (first token-less
  upload got 403), receipt finalised then a later PUT rejected (409) - transfer
  evidence is immutable after finalise.
- **Multi-activation honesty:** three consumer activations (first failed upload,
  token-path issue); all are in the ledger, none rewritten; verifier GAPs record the
  Sysmon entity-drop on first-connection E3s (receipt remains the transfer proof).
- **S4 alerts visible by default:** with S4 exported as a non-building-block rule,
  this run's stored alerts include **S4 = 6** (default Kibana filter view); 51 stored
  alerts total with per-alert ids in the run's alert-manifest (upper bounds).
- Misc: BOM-less JSON writes in guest probes; elevation/reboot scripts now run
  in-guest with explicit output paths; prepare_run no longer embeds the sink token in
  committed payloads (guest file %TEMP%\lab-token.txt + SYSTEM temp fallback).


## 2026-10-03 - Second remediation round: elevation honesty, sink hardening, ES field rules, host-bound joins

- **Elevation honesty (FIXED):** no run claims a UAC elevation. The reference runs start
  from a High-integrity operator session and capture no pre-chain Medium token, so the
  verifier now records `GAP S2: elevation unverified - mechanism observed` for every
  run; `scripts/elevation_preflight.ps1` implements the pre/post integrity measurement
  a real Medium-integrity run must capture, and the verifier FAILs when a run with
  measurements shows no Medium->High transition. attack-chain-plan / reports / README
  no longer infer elevation from the SYSTEM consumer (S4 SYSTEM proves the consumer
  context only; Microsoft distinguishes child-process tokens from a UAC grant).
- **Reboot survival (NOT YET EXECUTED - procedure added):** `scripts/reboot_survival_check.ps1`
  records before/after subscription-object checks + trigger verification. No guest
  reboot was performed in this round, so persistence-across-reboot remains UNVERIFIED
  (runbook documents the AV-on/AV-off requirement).
- **Sink hardening (FIXED):** `sink_server.py` binds the LAB interface by default
  (0.0.0.0 refused), authenticates uploads with a shared lab token (`X-LAB-Token` /
  `SINK_TOKEN`), and supports `POST /receipt/<run_id>/finalise` so a receipt cannot be
  overwritten after the run. `prepare_run.ps1` refuses sinks outside 192.168.x.x and
  injects the token into the staged consumer. Attribution claim is now precisely
  "the sink received these bytes from a lab-token holder" - not cryptographic
  attribution to the victim. consumer.ps1 checks EACH upload exit code and fetches the
  receipt back to verify run/host/size/sha256 before reporting success (exit 2 on
  failure).
- **ES field rules (FIXED):** es_verify now enforces REQUIRED fields per event type
  (event.code, host, channel, process.name/entity_id/user for E1; entity/dst/port for
  E3; file.path for E11/E23; WMI references for 19/20/21) - a field missing in ES is
  a FAIL; join fields missing in ES are a labelled GAP; ledger-vs-ES comparison covers
  parent.entity_id, user, registry.path, WMI references and destination port, with
  symmetric quote/escape normalisation. Negative tests cover receipt run/host/size/
  hash, cleanup FAIL, entity/path mismatch, path traversal and the elevation gate.
- **Host-bound joins (FIXED):** C3 and C5 now key their per-clause `by` with
  `host.name` alongside the ancestry/path key, so a same-path/same-entity join cannot
  cross hosts (verified on ES 9.5.3: both still match 1 in each run window, control 0).
  C2/R2 descriptions and notes now state explicitly they are host/time candidates,
  not proven registration-to-activation links (Sysmon 19/20/21 carry no object
  linkage).
- **Building-block consumption (FIXED):** S4 (upload-intent/exfil-analogue signal) is
  no longer exported as a building block - its alerts appear under default Kibana
  filters; the other 10 rules remain building blocks and the catalogue documents the
  consumption model.
- **Hash provenance (FIXED):** the staged-consumer hash is documented everywhere as a
  GUEST PROBE measurement (stored as `probe-svhw-hash.json` with source/time/host/path),
  never as an EID 11 hash field; install.ps1/prepare_run.ps1/runbook/attack-chain-plan/
  correlation-architecture no longer claim an EID 11 link ("DIRECT EVENT LINK"
  replaced by "MEASUREMENT LINK").
- **Payload hygiene (FIXED):** setup.bat saves and RESTORES the pre-existing
  ms-settings value (no destruction), drops the dead setup.hta branch; install.ps1
  removal is restricted to the lab namespace (never touches unrelated subscription
  objects).
- **Provenance dirty-tree (FIXED forward):** capture_provenance.py now records
  `working_tree_diff_sha256` (hash of the uncommitted diff) when the tree is dirty, so
  the commit plus the diff hash pins the actual source state that ran. The three
  historical runs were captured while dirty and that historical delta is not
  reconstructable - labelled "not captured" in reports; future runs must run from a
  clean commit or rely on the diff hash.
- **Do not rewrite history:** the three run ledgers keep their recorded events; the
  verifier's new S2 elevation GAP and the probe-file fallback apply without changing
  event refs.


## 2026-10-03 - Remediation round: strict acceptance, run scoping, provenance

Everything below is a response to an external review of `b874f26`; each item is FIXED,
DOCUMENTED LIMITATION, or NOT VERIFIABLE WITH AVAILABLE EVIDENCE.

**P0 builder / run scoping (FIXED)**
- `scripts/build_ledger_run.py` now requires an explicit finite window
  (`RUN_WINDOW_START/END`, no implicit `now`), resolves the entry with a DESCENDING
  query and aborts on ambiguity, filters refs to the window, paginates with
  `search_after` (truncation reported, never silent), and keeps baseline
  (collector) E3 traffic in a separate `baseline_telemetry` block instead of S6.
- Only entity-verified curl E3s aimed at the sink enter S6; refs are de-duplicated by
  ES `_id`; stage status is `OBSERVED` (the builder does not self-certify PASS).
- Ledger now records `created_utc` (ledger write time) **and** `run_started_utc`
  (S1 event) plus `run_window_utc`.
- All three run ledgers were rebuilt with the new builder (RUN-03: 22 refs / 22 unique
  ids, 38 collector E3s separated).

**P0 verifier (FIXED)**
- `_check_placeholders()` is now called; ISO-8601 UTC timestamps, numeric event codes,
  `es_id` presence and per-stage required fields are enforced; duplicate event refs
  inside a stage fail; artifact paths are checked for traversal/absolute escapes.
- ES re-verification compares timestamp, event code, host, and the ledger's join /
  destination fields, handles 0/multiple hits explicitly, de-duplicates by `_id` and
  reports refs vs unique documents; acceptance is labelled **ACCEPTED (ES-BACKED)**
  versus **ACCEPTED-LEDGER-ONLY**, and the aggregate line no longer claims an
  unconditional "ALL RUNS ACCEPTED" when a run was ledger-only.
- S4 assertion strengthened (consumer must be SYSTEM with parent WmiPrvSE/scrcons;
  trigger must precede the consumer; missing parent name is a GAP, not a silent pass).
- S6 checks EVERY curl E1 against an entity-matched E3 to the sink destination, with
  ordering; a foreign-entity sink E3 is a contradiction (FAIL), absent attribution is
  a GAP. S3 module hash is required for acceptance. C2 compares normalised object
  references (not substrings) and requires an ordered, in-window sequence. S7 parses
  the cleanup artifact, checks `run_id` and every check result. Receipt validation
  binds run/host, validates size/sha256/filenames and compares the receipt manifest
  hash directly against the ledger ART-06-01 hash.
- Archive bytes are gitignored: the receipt is the committed transfer evidence; the
  verifier verifies bytes only when the archive is actually present and says so.

**P0 EQL / rules (FIXED, correcting an earlier wrong claim)**
- Verified on Elasticsearch 9.5.3 that EQL **supports a per-clause `by` key**: C3 now
  joins interpreter `process.entity_id` to discovery `process.parent.entity_id`, and
  C5 joins zip create/delete by `file.path`. The previous "EQL cannot bind asymmetric
  fields" statement was wrong and has been removed from the docs.
- `tools/validate_repository.py` now compares the normalised content of all 11 `.eql`
  sources against their exported queries (a one-character drift fails), with a
  negative test.
- S4 mapping corrected: it is an **E1-only upload-intent lab analogue**; the T1041 tag
  was removed and the rule is described as not proving a connection, a C2 channel or a
  successful transfer (receipt proves the transfer).

**P1 evidence / provenance / docs (FIXED where possible)**
- Stored alerts for RUN-03 exported with ids/timestamps/ancestry to
  `evidence/runs/RUN-20261003-03/alert-manifest.json`; the report distinguishes stored
  alerts (upper bound, re-matching explained by alert timestamps) from EQL clusters.
- Ledgers carry a `provenance` block (commit, Sysmon config hash, rule-export hash,
  observed versions, sink receipt hash); anything not captured is labelled
  "not captured" (the commit is the capture-time HEAD - documented, not implied).
- Report timestamps that were minute-approximations are labelled as such; the counts
  "22 refs / 22 unique ids" are stated explicitly.
- Root README, detection catalogue, telemetry contract, attack-detection mapping
  (marked HISTORICAL), reports/docs/scripts/payloads indexes and the review snapshot
  (marked SUPERSEDED) all describe the same current state; the CI workflow claims only
  what it runs.

**Documented limitations (unchanged, restated)**
- High-integrity operator session: the UAC bypass mechanism is replayed without a
  Medium->High transition; no reboot-survival test; in-process discovery not
  independently evidenced; receipt is not an archive-byte check; the 5-minute idle
  control is a negative check, not a false-positive rate.


## 2026-10-03 - RUN-20261003-03 (final export) and E3-by-entity resolution

- E3 attribution resolved at the technical key: Sysmon emits the curl E3 with `Image: <unknown process>` (process.name empty) but with the correct process.entity_id; the ledger now stores all window E3s and the verifier joins E1<->E3 BY ENTITY (GAP only when the entity is also missing). RUN-20261003-02 rebuilt and verified with this join (S6 ownership OK, name-less annotation kept).
- Executed RUN-20261003-03 with the final 11-rule export live in Kibana: ledger `evidence/runs/RUN-20261003-03/` (56 event refs), verifier ACCEPTED (ES re-verification, module + binding + entity ownership + path joins). Detection: 14 unique clusters / **25 stored alerts**, incl. **S4 = 2 stored alerts** (E1-only upload-intent signal). Report `reports/reference-run-20261003-03.md`.

## 2026-10-03 - Kibana synced with the final 11-rule export

- Deleted the OLD S4 (Curl Upload-Intent Process Making a Network Connection, id 6e5813cb...) from Kibana and imported the current export: 11 rules, 0 errors.
- Verified via `_find`: all 11 names present, deterministic rule_id values match the repository export, enabled, building_block_type=default; no stale S4 name remains.

## 2026-10-03 - S4 kept and redesigned; ledger window fix

- S4 kept (per review) and rewritten as a SINGLE-EVENT E1 signal: curl spawned by a
  script/interpreter (powershell/cmd/wscript/cscript) with upload-intent arguments;
  no archive name/IP/port/hostname; NO E1-E3 host/time join (that would risk
  misattributing another process' connection to this curl). Name: "[S4] Script-
  Spawned Curl with Upload Arguments". It proves upload INTENT; E1<->E3 ownership is
  the verifier S6 ledger join, recorded as **GAP** when the curl E3 lacks attribution;
  transfer success stays proven by the sink receipt.
- Ledger builder window fix (correctness): the generic builder anchored on the OLDEST
  setup.bat event, letting run-01/attempt-1 events leak into RUN-20261003-02 and
  producing an unreliable ACCEPTED. Now anchors on the LATEST setup.bat launch with a
  60 s pre-buffer; RUN-20261003-02 rebuilt (20 genuine events) and re-verified
  ACCEPTED with `GAP S6` recorded.
- E3 attribution root cause: run-02 curl E3s carry `Image: <unknown process>` - Sysmon
  LOCAL attribution failure (the ES message text comes from Sysmon's local record);
  ingested E3s have entity but no process.name, so E1<->E3 ownership is a gap, not a
  failure and not a forced host/time match.
- Re-evaluation with the redesigned S4: 11/11 rules in both run windows (S4 = 2
  clusters each), 0/11 in the idle control window.

## 2026-10-03 - RUN-20261003-02 (live-alert re-run)

- Re-ran the chain with the 11 rules live in Kibana: ledger
  evidence/runs/RUN-20261003-02/, verifier ACCEPTED (ES re-verification, module +
  binding + ancestry/path joins; S4's E3 ownership recorded as GAP in this run).
- First attempt aborted and reverted: leftover run-01 objects made Set-WmiInstance
  update rather than create, so EID 20/21 Created were absent. install.ps1 removal
  hardened (verified purge incl. Dsh* debris) and the chain re-ran on a clean window;
  the abort is recorded as a retry.
- Detection: unique EQL clusters 11/11 (run02), stored alerts are upper bounds (1 m
  interval / 2 m lookback re-matches); S4's E1 signal fired (2 clusters) while the
  curl E3 lacked process attribution (telemetry-quality finding; receipt is the
  transfer proof). Generic ledger builder added (scripts/build_ledger_run.py).

## 2026-10-03 — Kibana import and live-alert smoke

- Imported the 11 rules into Kibana: all found, enabled, `building_block_type=default`,
  deterministic `rule_id` values match the repository export (verified via
  `api/detection_engine/rules/_find` over the SSH tunnel).
- Live smoke (separate window; NOT part of RUN-20261003-01): a registry
  `ms-settings` write+delete in the guest produced 2 EID 13 events; **R1 stored 2
  alerts at 2026-10-03T10:37:16Z** (schedule + lookback worked); the other 10 rules
  stored 0 alerts (negatives still clean). The RUN-20261003-01 window predates the
  import, so the report's per-rule numbers remain query-level (report §4) — this
  smoke proves the import → schedule → query → alert pipeline end-to-end (§3.1).

## 2026-10-03 — review-driven rule and verifier revision (post RUN-20261003-01)

- **Ledger/artifact fix for fresh checkouts**: the received archive was referenced in
  the artifact_index but is `*.zip`-gitignored — removed from the index; the sink
  receipt (name/size/sha256) is the committed transfer evidence. Verifier now ACCEPTED
  without the archive file present; the repository validator now scans nested run
  directories (`evidence/runs/RUN-*/RUN-*.json`) instead of only the top level.
- **Verifier chain joins**: added `join_checks` over the ledger's stored fields —
  fodhelper→wscript→powershell ancestry, consumer under WmiPrvSE (parent entity),
  interpreter→arp ancestry, curl E1↔E3 ownership, archive create/delete same path,
  C2 binding references (EID21 Consumer/Filter vs EID19/20 names). EQL's inability to
  bind asymmetric fields was verified on the lab stack (ES 9.5.3) and is documented,
  not asserted away.
- **Ledger richness**: refs now store entity / parent entity / file path / destination
  / registry / WMI reference fields (built by `scripts/build_ledger_run01.py`); the S3
  module-hash provenance is explicitly labelled "guest probe" (the EID11 event carries
  no Hashes on this stack) — no longer presented as an event field.
- **Rules revised per the review** (renames change ids; delete old server-side):
  R1 → ECS `registry.path`/`value`, SID-free, case-insensitive; C1/S1/S3 → case-
  insensitive comparisons + host/entity suppression; S2 → encoded branch independent
  of hidden, parent-name exclusions removed; C2 → name-identity exclusions removed;
  R2 → deployment-agnostic registration→WMI-hosted interpreter (no notepad/svhw);
  C3 → host/time correlation with ancestry at the verifier; C4 → single-entity
  staging→archive (network split out); S4 → curl upload-intent + entity-owned
  connection (no port/IP lists); C5 → archive create→delete (path via verifier, no
  PowerShell status dependency). All exports carry `building_block_type=default`.
- **Re-evaluation**: 11/11 rules match the RUN-20261003-01 window; 0/11 in the idle
  control window (2026-10-03 10:00–10:05Z). Report §4 updated accordingly.

## 2026-10-03 — first verified run (RUN-20261003-01)

- Executed the S1–S7 chain on the lab VM `wmi` (Win10 19045, Sysmon 15.21, internal
  sink at 192.168.106.1:9180, Elastic 9.5.3); ledger `evidence/runs/RUN-20261003-01/`:
  real es_id + @timestamp per stage, artifacts indexed, verifier **ACCEPTED** (incl.
  ES re-verification of 21 events and the S3 module-integrity join).
- Transfer integrity proven: sink receipt sha256 == guest-computed ZIP_SHA256
  (6A6303…, 14188 B); manifest canonical hash matches the receipt.
- Detection re-evaluation: 8/11 rules match the run (R1=2, C1/S1/S2/C2/C3/R2/S3=1);
  C4/S4/C5 = 0 by design (web-port/private-IP scope excludes the internal sink; the
  transfer is proven by the receipt). Report: `reports/reference-run-20261003-01.md`.
- Rule fixes surfaced by the run: R1 rewritten to ECS `registry.path` (the raw
  `winlog.event_data.TargetObject` is not mapped on this stack); S2 dropped the
  unmapped `winlog.event_data.CommandLine` fallback; both regenerated with stable
  deterministic ids and re-evaluated (R1=2, S2=1). Lib/validator/offline tests pass.
- Sysmon config: confirmed empirically on Sysmon 15.21 that an **absent** Network/
  Registry/WMI section does NOT log those event types, while an explicit empty
  `onmatch="exclude"` section does — the config was updated to the explicit form.
- Verifier ES re-verification switched to the `ids` search (single-doc GET does not
  support the data-stream wildcard).

## 2026-10-03 — run-day refinements after the Phase 0–2 restructure

- `config/sysmon-config.xml`: removed the three empty `onmatch="exclude"` blocks
  (Network/Registry/WMI) whose runtime behaviour is ambiguous ("exclude nothing" vs
  "exclude all"); a section-less event type logs all events, which the chain needs.
- Verifier: ES-backed re-verification (re-fetch each recorded event by `es_id` and
  assert the stored timestamp matches the ledger, within tolerance); URL-safe `es_id`
  handling; S3 module-integrity assertion (Sysmon EID 11 `Hash` == raw sha256 of the
  staged consumer ART-01-02).
- `scripts/prepare_run.ps1`: run-scoped payload staging with run id / sink base /
  host substitution, output under `evidence/runs/<run_id>/payload/`, prints the
  staged consumer sha256; `install.ps1` now materializes `svhw.ps1` with byte
  fidelity (no BOM, no line-ending conversion) so the module-integrity link holds.
- Generator: fixed the MITRE `threat` JSON shape (PowerShell array-subexpression
  flattening corrupted nested subtechniques; singleton arrays unrolled) and added a
  structural regression test; validator now checks export field completeness.
- Docs: runbook/chain-plan/correlation-architecture updated for staged payloads and
  the module-integrity join; scenario-analysis paths aligned to the new layout.

## 2026-10-03 — evidence architecture and repository restructure (Phase 0–2)

Driven by the Phase 0 gap audit (detection basis missing repo-wide; no run-scoped
evidence; no acceptance verifier; join keys undocumented; C1 lacked the registry
stage; no activation stage; C4/C5 curl-vs-PowerShell mismatch; severity/tag
inflation). Every change below maps to a finding in that audit:

- **Phase 1 — evidence architecture**
  - Added `evidence/runs/RUN-schema.json`: run ledger with `additionalProperties:
    false`, explicit `NOT RUN` statuses, event rows carrying real `es_id` +
    `@timestamp`, artifact index with canonical/raw hashes.
  - Added `scripts/verify/verify_run_evidence.py`: per-stage acceptance assertions,
    fail-fast on unknown runs, `--all` regression, transfer-receipt integrity;
    `scripts/verify/fetch_evidence_ids.py`: ES event fetch for ledger rows;
    `scripts/evidence_lib.py`: pure, testable evidence helpers.
  - Added `docs/correlation-architecture.md`: join keys (process `entity_id`
    ancestry; EID 21 binding references ⇄ 19/20 names; transfer hash equality),
    evidence tiers (DIRECT / SUPPORTED HANDOFF / TEMPORAL-CONTEXTUAL / UNPROVEN /
    CONTRADICTED), sensor/ingest checklist.
  - Added `docs/attack-chain-plan.md` (S1–S7 with per-stage telemetry, evidence and
    explicit boundaries) and `docs/architecture.md` (single-host topology, sink).
- **Phase 2 — restructure to the reference layout**
  - Layout: `docs/`, `evidence/runs/RUN-<date>-<seq>/`, `detections/` (catalogue +
    `queries/*.eql` + `exports/*.ndjson`), `reports/`, `scripts/tests/`,
    `payloads/`; historical screenshots moved to `evidence/sanitized-screenshots/`
    (provenance only, not run evidence).
  - `scripts/rules/gen_rules_ndjson.ps1`: deterministic export (rule_id =
    SHA-256(name), v5 shape); 11 rules = 9 historical predicates preserved
    verbatim + 2 new: R1 (ms-settings registry stage, closes the UAC coverage gap;
    basis Sigma `46dd5308`) and R2 (notepad-triggered consumer activation, closes
    the activation coverage gap; basis MITRE DET0086/AN0236).
  - Detection basis added to every rule's `setup` (MITRE detection strategy + Sigma
    rule ids + vendor references); severities/tags normalised to the building-block
    taxonomy (historical "Critical"/"High Fidelity" tags dropped).
  - Payloads split and simplified: `payloads/setup.bat` (entry + UAC bypass),
    `payloads/install.ps1` (consumer materialisation with run-scoped config +
    run-id read-back check + idempotent WMI registration), `payloads/consumer.ps1`
    (discovery/collection/archive/exfil/cleanup). Exfil now targets the internal
    sink (`scripts/sink_server.py`) with an ART-07-01 receipt — Telegram and other
    external channels are out of scope by design.
  - Added `scripts/tests/test_offline.py` (rule-id uniqueness/determinism, ledger
    schema negative cases, verifier negative cases, receipt negatives) and rewrote
    `tools/validate_repository.py` + CI for the new layout.

## VM readiness checklist (Phase 3 gate — confirmed before the first run)

1. Victim VM: Windows 10/11 Pro, workgroup; victim account = local Administrators
   member running with a filtered (medium-integrity) token. No AD.
2. Sysmon installed with `config/sysmon-config.xml`; **prove** EID 1/3/11/13/19/20/21
   /23 reach the channel locally AND in Elastic (per-run probe; the empty
   `<WmiEvent onmatch="exclude">` block must be shown not to suppress 19/20/21;
   check E255/ingest errors).
3. Elastic Agent enrolled and shipping Sysmon + Security channels to the lab's
   Elastic stack; ES creds to the operator via environment only.
4. Clock: guest UTC aligned with the lab host (one probe artifact per run).
5. VM snapshot taken before the run; cleanup probe (ART-08-01) after.
6. Exfil channel configured to the internal sink (repo host, port documented per
   run); no external services.

## 2026-09-25 — rule metadata and telemetry corrections

- Replaced all nine embedded setup guides, including stale fallback claims, unsupported false-positive claims, outdated configuration descriptions and incorrect Sysmon deletion guidance.
- Renamed rules to describe their actual event patterns; retained prefixes and rule_id values for historical traceability. Incremented metadata versions.
- Added field dependency metadata and a telemetry contract covering event categories, actor context, token/integrity distinctions, archive/file hashes, suppression and scheduling.
- Corrected query comments while preserving executable query predicates, schedules, suppression, severity and ATT&CK tags.
- Documented delivery provenance gaps, generated-file matches in C4, and cleanup evidence boundaries.
- Added offline checks for field coverage, event-source descriptions and known overclaim regressions. Live correlation attribution and timing still require source events; this update does not claim to resolve them.

## 2026-09-25 — attack-to-detection mapping

- Removed the prospective validation plan and blank run-record template from the published documentation.
- Added a behavior-to-telemetry-to-rule mapping with links to retained evidence, process/object relationships, and overlapping rule coverage.
- Replaced the README technique list with a concise mapping of implemented detection work and observed alerts.
- Preserved scenario code, rule queries, and evidence images unchanged.

## 2026-09-25 — evidence-based documentation refresh

Baseline: `43a7141c7753058e58bfb0894d4123236ce3d1b9`.

- Replaced the Word report with a Markdown case study, a partial UTC event timeline, and an explicit telemetry-coverage assessment.
- Retained seven selected original screenshots unchanged, with source-image provenance and SHA-256 values. Removed the Word file from the current tree; its historical version remains in Git.
- Rewrote README around implemented behaviors, observed results, and verified scope. Added static scenario analysis and a source map.
- Removed the unimplemented playbook, duplicated limitations document, and unsupported performance/AV-evasion claims. Separated measured observations from unverified claims.
- Corrected the malformed Sysmon XML comment without changing filter conditions.
- Removed notification actions/connectors and environment-specific export metadata. Owner-side credential rotation is still required.
- Aligned descriptions, false-positive caveats, and notes with query scope. Preserved rule IDs, queries, names, enabled state, schedules, severity, filters, and original ATT&CK tags.
- Added offline validation and CI. Scenario scripts and the delivery page remain byte-for-byte unchanged.

## Verification scope

Offline checks cover XML syntax, NDJSON rule inventory, export hygiene, documentation links, and evidence hashes. Comparisons against the baseline check preservation of executable artifacts and detection queries. Windows configuration acceptance, Elastic import/EQL execution, detection accuracy, and response remain unvalidated by these checks.
