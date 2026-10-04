# Reference Run Report — RUN-20261003-04 (Medium-integrity start + reboot survival)

Window: **2026-10-04T08:15:00Z – 08:23:00Z**. Ledger + artifacts:
`evidence/runs/RUN-20261003-04/`. Verifier:
`scripts/verify/verify_run_evidence.py RUN-20261003-04` → **ACCEPTED (ES-BACKED)**
(49 event refs across 49 unique documents re-fetched).

## 1. What is different about this run

- **Medium-integrity start (the elevation test).** The chain was launched from the
  filtered token of the local Administrator `wmi\duc` (SID
  S-1-5-21-712721020-3028668141-2696198267-1001) via a LIMITED scheduled task
  (Medium Mandatory Level, S-1-16-8192) — **not** from a High-integrity operator
  session. `scripts/elevation_preflight.ps1` captured elevation-before (Medium,
  08:14:46Z) and `install.ps1` captured elevation-after (High, 08:15:09Z).
- **The verifier's S2 gate PASSES:**
  `ok S2 elevation: Medium (S-1-16-8192) → High (S-1-16-12288) (Medium->High observed)`.
- Corroborating per-event integrity (Sysmon EID 1 `winlog.event_data.IntegrityLevel`,
  re-fetched from ES): cmd/reg **Medium** at 08:15:06–07; fodhelper **Medium→High**
  (the auto-elevating trampoline, two instances then the elevated one at 08:15:07.275);
  wscript **High** (parent fodhelper) 08:15:07.582; install powershell **High**
  (parent wscript) 08:15:07.692; consumer powershell and curl **System**
  (parent WmiPrvSE) 08:15:29–32.
- Sink: interface-bound (192.168.106.1), token-authenticated, receipt finalised.
- **Reboot survival (AV-off pass)** is attached to this run (see §6): the guest was
  power-cycled and the subscription objects + trigger still worked.

## 2. Timeline

| Time (Z) | Stage | Observed |
|---|---|---|
| 08:14:46 | — | elevation-before captured in the LIMITED task (Medium, S-1-16-8192) |
| 08:15:06.850 | S1 | `cmd.exe` (Medium, parent svchost = scheduled task) runs setup.bat |
| 08:15:07.009/.029/.039/.052 | S2 | `reg.exe` delete/add/add (EID 13) — Medium |
| 08:15:07.073/.161/.275 | S2 | fodhelper Medium ×2 → **High** (auto-elevating trampoline) |
| 08:15:07.582 / .692 | S2 | wscript **High** → powershell **High** (`-f install.ps1`) |
| 08:15:09.424/.440/.515 | S3 | EID 19/20/21 Created (filter/consumer/binding) |
| 08:15:09 | S3 | elevation-after captured (High) |
| 08:15:25.398 | S4 | notepad trigger (vmrun, High) |
| 08:15:29.654 | S4 | consumer powershell **System** (parent WmiPrvSE) |
| 08:15:32 | S6 | curl ×2 (System); first attempt had no token (consumer temp path) → 403 |
| 08:15:34 | S6 | curl E3 to sink (2× name-less, 1 powershell) |
| 08:17:55 / 08:20:28 | S4/S6 | retriggers after token fix; final upload OK |
| 08:2x | S6 | receipt ART-07-01 (wdmp.zip 16,264 B) written |
| 08:23 | — | run window closes; verifier ACCEPTED; receipt finalised (later PUT → 409) |
| 08:29:29 | reboot | guest power-cycled (LastBootUpTime 15:29:29+07) |
| 08:40:20 / .21 | reboot | notepad → consumer (parent WmiPrvSE, SYSTEM) — persistence alive |

## 3. Per-stage verification

| Stage | Status | Asserted |
|---|---|---|
| S1 | PASS | entry cmd E1 at 08:15:06.850 (Medium) |
| S2 | PASS | EID 13 registry path; fodhelper→wscript→powershell ancestry by entity; **elevation Medium→High observed** (measurements + E1 IntegrityLevel) |
| S3 | PASS | EID 19/20/21 Created, ordered, in-window; binding references equal; probe hash == staged consumer (A9E0BFF5…) |
| S4 | PASS | consumer SYSTEM, parent WmiPrvSE, after trigger |
| S5 | PASS | ARP.EXE + staging writes |
| S6 | PASS | 4 curl E1→E3 ownerships by entity to 192.168.106.1:9180 (2 GAPs: Sysmon dropped entity on two connections — receipt proves transfer); local archive bytes match receipt; PS status E3 owned by consumer |
| S7 | PASS | wdmp.zip delete same path; cleanup artifact parsed, run-bound, all checks PASS |

GAPs (recorded, not failures): `S6 … Sysmon dropped entity attribution on this
connection - transfer proven by receipt` (×2) and `ES … (attribution lost) - SENSOR
GAP` (×2) — the first of two rapid curl connections per activation loses attribution
on this Sysmon stack; the manifest-connection E3 of the same activation is
entity-matched, and the sink receipt binds name/size/sha256/run/host.

## 4. Detection results — stored alerts (operational, rules live)

`evidence/runs/RUN-20261003-04/alert-manifest.json`: **51 stored alerts** (R1=2,
C1=1, S1=1, S2=4, C2=4, R2=3, S3=3, C3=9, C4=9, **S4=6**, C5=9). S4 is exported
WITHOUT `building_block_type`, so its alerts appear under default Kibana filters —
one objective of this round. Stored alerts are upper bounds: this window contains
three consumer activations and 1 m/2 m schedule re-matching re-evaluates the same
clusters; the manifest carries per-alert ids/timestamps for independent inspection.
Direct EQL re-evaluation would yield fewer unique clusters; the two quantities are
kept separate (see detections/README.md).

## 5. Sink contract exercised

- Sink bound to 192.168.106.1 (not 0.0.0.0); uploads without the lab token → 403
  (the first, token-less attempt).
- Receipt finalised via `POST /receipt/RUN-20261003-04/finalise`; a later PUT was
  rejected with **409** (transfer evidence immutability).
- Attribution claim: "the sink received these bytes from a lab-token holder" — not
  cryptographic victim attribution.

## 6. Reboot survival (AV-off)

`evidence/runs/RUN-20261003-04/reboot-survival.json`: guest power-cycled at
08:29:29Z; post-boot probe shows `NotepadFilter=1, SystemDumpConsumer=1, binding=1,
svhw.ps1 present`; notepad trigger at 08:40:20.227Z fired consumer powershell E1
`AaEGEjMycFpEpRZGWiM-` at 08:40:21.543Z (parent WmiPrvSE, user SYSTEM, integrity
System). **Windows Defender was STOPPED in the guest (AV-off pass).** An AV-on pass
is not yet executed — the procedure is identical
(`scripts/reboot_survival_check.ps1`, `-Mode before` → reboot → `-Mode after
-TriggerNotepad`), and no persistence-vs-AV claim is made until it runs.

## 7. Limitations

- Elevation evidence covers the **filtered-token → High transition of the UAC bypass
  mechanism** (fodhelper auto-elevation); the consumer additionally runs as SYSTEM.
  This is the mechanism the chain uses; it is not an exploit of a new vulnerability.
- Reboot survival was only tested with AV off.
- The first consumer activation failed upload (token path), so three activations are
  in the window; each is documented in the ledger, none rewritten.
- Stored alerts are upper bounds (see §4); control-window/re-baselining is unchanged.

## 8. References

- Ledger + artifacts: `evidence/runs/RUN-20261003-04/`
- Alert manifest: `evidence/runs/RUN-20261003-04/alert-manifest.json`
- Reboot survival: `evidence/runs/RUN-20261003-04/reboot-survival.json`
- Elevation tools: `scripts/elevation_preflight.ps1`, verifier "S2 elevation gate"