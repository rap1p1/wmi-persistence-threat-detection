# Reference Run Report — RUN-20261003-02

Window: 2026-10-03 10:46:00Z – 10:49:30Z. Ledger + artifacts:
`evidence/runs/RUN-20261003-02/`. Verifier:
`scripts/verify/verify_run_evidence.py RUN-20261003-02` → **ACCEPTED**
(ES re-verification, 25 events). This run used the **live Kibana rules** (imported
2026-10-03), so the detection numbers come from **stored alerts**, not query-level
re-evaluation.

Attempt 1 of this run was aborted (revert to `before-run-20261003-02`): leftover
subscription objects from run-01 made `Set-WmiInstance` update instead of create, so
EID 20/21 Created were not generated. `install.ps1` removal was hardened (verified
purge incl. `Dsh*` debris) and the chain re-ran cleanly — this report covers the
clean window only.

## 1. Context / scope

Same personal-host lab as run-01 (victim `wmi`, Win10 19045, account `Duc` in
Administrators; operator-launched via vmrun at High integrity — mechanism replay, as
documented). Sysmon 15.21 + repo config, Elastic Agent shipping, internal sink
192.168.106.1:9180, rules live in Kibana (11, enabled, building-block mode).

## 2. Timeline (real event times)

| Time (Z) | Observation |
|---|---|
| 10:46:09.615 | S1 — `cmd.exe` runs `setup.bat` |
| 10:46:09.880 | S2 — elevated PowerShell install (parent wscript) |
| 10:46:11.420 / .436 / .483 | S3 — EID 19 Created `NotepadFilter`; EID 20 Created `SystemDumpConsumer`; EID 21 Created binding (**gate PASS**; hard-gated on 19/20/21 all Created) |
| 10:46:36.008 | S4 — `notepad.exe` (trigger) |
| 10:46:36.565 | S4 — consumer `powershell` under `WmiPrvSE.exe` (SYSTEM, `-f …svhw.ps1`) |
| 10:46:38.557 / .592 | S6 — `curl.exe -T wdmp.zip`; `curl.exe --data-binary _manifest.txt` |
| 10:46:41.097 | S7 — cleanup `cmd /c … rd wdmp & del wdmp.zip` |
| 10:46:41.991 | S6 — network to `192.168.106.1:9180` (curl E3 lacks process attribution in this window; PS status E3 present) |
| 10:46:17.9–18.1 | First stored alerts (C1/S1 10:46:17.9, C2 10:46:18.162) |

## 3. Per-stage evidence table

| Stage | Status | Evidence (es_id / ts) | Boundary / note |
|---|---|---|---|
| S1 | PASS | E1 cmd 10:46:09.615 | operator action (vmrun), declared |
| S2 | PASS | EID13 reg.exe; E1 fodhelper→wscript→ps | registry→fodhelper TEMPORAL; ancestry verifier-checked |
| S3 | PASS | EID 19/20/21 Created 10:46:11.4; EID11 svhw.ps1 10:46:11 (no Hashes; guest hash `01825657…` == staged consumer) | module integrity; binding refs verifier-checked (NotepadFilter / SystemDumpConsumer) |
| S4 | PASS | notepad 10:46:36.008; consumer 10:46:36.565 (parent WmiPrvSE) | activation; consumer as SYSTEM |
| S5 | PASS | ARP + info.txt/_manifest.txt staging | in-process queries not independently evidenced |
| S6 | PASS | zip create; curl E1 x2; E3 to :9180; PS status E3; receipt `ART-07-01` (wdmp.zip 14653 B) | archive create by consumer entity; the curl E3 lacked process attribution in this window; receipt = transfer proof |
| S7 | PASS | EID23 wdmp.zip 10:46:41.097+; create/delete same path (verifier) | cleanup verified post-run (`ART-08-01`) |

## 4. Detection results — live alerts (RUN-20261003-02)

| Rule | Unique clusters (EQL re-run) | Stored alerts (upper bound) | Notes |
|---|---|---|---|
| R1 | 2 | 2 | ms-settings `(Default)` + `DelegateExecute` |
| C1 | 1 | 1 | wscript under fodhelper |
| S1 | 1 | 1 | same event as C1 (overlap) |
| S2 | 2 | 2 | install PS + consumer PS (overlap with S3/R2) |
| C2 | 1 | 4 | one registration cluster re-alerted across 1 m evaluations/lookback |
| R2 | 1 | 3 | registration → WMI-hosted interpreter |
| S3 | 1 | 1 | consumer powershell |
| C3 | 1 | 3 | interpreter → discovery (ancestry verifier-checked) |
| C4 | 1 | 3 | staging → archive by the consumer entity |
| S4 Script-Spawned Curl with Upload Arguments | 2 | 0* | upload-intent E1 signal (redesigned AFTER this run; at run time the live rule was the older E3-joining S4, which stored 0). Current-export clusters = 2 (both curl E1s) |
| C5 | 1 | 3 | wdmp.zip create → delete, same path (verifier) |

**That is 14 unique clusters under the current export; 23 stored alerts were recorded
under the rules live at run time** (the older S4 stored 0 because it required an E3
join; the current S4 is E1-only and matches 2). Stored-alert counts are **upper
bounds**: with a 1 m interval and a 2 m look-back the same event cluster is re-matched
across consecutive evaluations; suppression groups bound within-run merging but do not
collapse cross-evaluation alerts. Unique clusters come from the direct EQL re-run over
the window. None of the alert counts imply distinct incidents (building-block mode).

## 5. Limitations (honest)

- Operator-launched High-integrity session; the fodhelper UAC mechanism is replayed,
  not a demonstrated Medium→High transition (S4's SYSTEM consumer is the only
  elevation-path evidence).
- **S4 E3 attribution gap**: the curl E3 in this window carried `Image: <unknown
  process>` (Sysmon local attribution failure — verified identical in the guest local
  log), so the verifier records `GAP S6` for E1↔E3 ownership; S4's upload-intent E1
  signal still fired (2 clusters). Transfer success rests on the receipt
  (name/size/sha256, 14653 B, verified).
- Attempt-1 abort (EID20/21 not generated due to create-or-update semantics on
  leftover objects) recorded as retry; install.ps1 removal hardened and re-verified.
- Alerts reflect schedule/lookback re-matching; counts are upper bounds (see §4).
- EQL asymmetric joins (ancestry/ownership/path) enforced by the verifier, as
  documented in `docs/correlation-architecture.md` (verified ES 9.5.3 limitation).
- No reboot-survival test; subscription left installed by design (recovery = revert
  snapshot or remove; `ART-08-01`).

## 6. Recovery / cleanup

- Snapshot `before-run-20261003-02` (pre-attempt-1) and the revert-based clean window
  used for this run; subscription re-installed by design.
- Sink stopped after evidence; guest verified clean of `wdmp.zip`/`wdmp`.

## 7. References

- Ledger + artifacts: `evidence/runs/RUN-20261003-02/`
- Rules + detection basis: `detections/README.md` · joins: `docs/correlation-architecture.md`
- Chain: `docs/attack-chain-plan.md` · verifier: `scripts/verify/verify_run_evidence.py`
- Builder (generic): `scripts/build_ledger_run.py`