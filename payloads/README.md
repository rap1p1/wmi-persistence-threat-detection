# payloads — run-scoped artifacts

| File | Responsibility | Evidence relationship |
|---|---|---|
| `setup.bat` | S1/S2 entry + UAC bypass: writes the ms-settings `Open\command` hijack and the temporary script-host proxy, triggers `fodhelper.exe`, removes both after ~3 s | Registry EID 13 (R1), E1 fodhelper/wscript (C1/S1), E1 elevated PowerShell (S2) |
| `install.ps1` | S3 persistence install (elevated, hidden): materializes the consumer as `C:\Windows\Temp\svhw.ps1` with the run-scoped config, removes any prior subscription, registers filter/consumer/binding | EID 11 consumer write; EID 19/20/21 (C2) |
| `consumer.ps1` | S4–S7 consumer (SYSTEM): discovery, collection, staging, manifest, archive, sink transfer, status message, cleanup | EID 1 arp / EID 11 staging (C3/C4); curl E1/E3 + sink receipt (S4/Transfer); EID 23 (C5) |

The three files are used together: the operator copies this directory into the guest,
runs `setup.bat` from an interactive session of the victim account, and starts
`notepad.exe` (S4) after install. `install.ps1` injects `__RUN_ID__` /
`__SINK_BASE__` / `__HOST__` into the materialized consumer and verifies the run id is
present inside the written file before registration (config-carry-over check).

The historical single-file `scripts/payload.ps1` (embedded consumer + Telegram)
was replaced by this split layout with an internal sink; git history retains the
original. Telegram and other external channels are out of scope by design
(docs/attack-chain-plan.md, S6).

See `../scripts/runbooks/README.md` for the operator runbook.