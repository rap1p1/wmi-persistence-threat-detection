# Architecture — WMI Persistence Lab

## Overview

Single-host personal-workstation scenario: one Windows guest plays the victim; the
repo host runs the internal sink and (optionally) the Elastic stack. No Active
Directory, no domain, no external services. The attacker story is a normal user
running a script that abuses UAC (fodhelper) and installs WMI persistence; endpoint
telemetry (Sysmon via Elastic Agent) is evaluated with Elastic Security rules.

Status: **design intent** — verified operational states are asserted only after a run
moves through the sensor/ingest checklist (`correlation-architecture.md` §6).

## Network and hosts

```text
victim ── lab network ──> lab host
   |                          +-- Elasticsearch / Kibana / Fleet (when hosted here)
   |                          +-- scripts/sink_server.py  (port documented per run)
   +-- Sysmon -> Windows Event Log -> Elastic Agent -> Elastic
```

| Host | Role | Identity |
|---|---|---|
| `victim` | Windows 10/11 Pro, workgroup | local user `victim`, member of local Administrators (runs with a filtered token = the fodhelper prerequisite); one separate local admin account for operator-only tasks if needed |
| `lab` | repo host | runs the sink and Elastic integration; ES creds are environment-only (`ES_URL`, `ES_USER`, `ES_PASS`) |

The guest needs no internet access; the exfil destination is the internal sink
(port documented per run), keeping transfer evidence internal and reversible.

## Telemetry path

1. Sysmon (`config/sysmon-config.xml`) writes to
   `Microsoft-Windows-Sysmon/Operational`.
2. Elastic Agent ships Sysmon + Security channels into Elasticsearch.
3. Elastic Security evaluates the rules from `detections/exports/*.ndjson`
   (interval 1 m, look-back 2–3 m per rule; suppression on host/entity groups).

### Sysmon config notes

- Event IDs exercised by the chain: 1, 3, 11, 12, 13, 14, 19, 20, 21, 23.
- `HashAlgorithms = md5,sha256,imphash`; revoke check off.
- `<FileCreate>` includes `\Windows\Temp\`, `\Users\Public\`, `\ProgramData\`,
  `\AppData\Local\Temp\` and script/archive extensions; `<FileDelete>` mirrors those
  paths and the .zip/.ps1/.vbs extensions.
- `<WmiEvent onmatch="exclude">` is intentionally empty; the empty exclude list is
  expected to log all WMI events, and the first run must **prove** EID 19/20/21 reach
  the channel (local + ingested) before any C2 claim.
- `<NetworkConnect>` and `<RegistryEvent>` are pass-all (empty exclude lists).
- Image-load (EID 7), process-access (EID 10), DNS and file-delete-archive are not
  part of this chain's evidence; if a future chain needs them, add +
  re-verify, never assume.

## Sink (internal transfer target)

`scripts/sink_server.py` listens on the lab host (default port 9180, configurable and
documented per run):

- `POST /upload` — multipart fields: `file` (the archive), `run` (run id), `host`
  (host name), `manifest` (in-guest `_manifest.txt` text). The server writes the
  uploaded file into `evidence/runs/RUN-<id>/` and writes a receipt JSON
  (`ART-07-01-<run>.json`) with the observed file name/size/sha256 (raw bytes) and
  the canonical manifest hash (CRLF→LF normalised).
- `POST /status` — receives PowerShell status/notification JSON (this is the traffic
  that C4/C5's PowerShell network stage may match; the ledger attributes it).
- Receipts never carry credentials; run id is validated against the expected pattern.

## Reproducibility and hygiene

- Deterministic rule ids (`scripts/rules/gen_rules_ndjson.ps1`) so re-imports
  overwrite instead of duplicate; rename ⇒ delete server-side, then import.
- Ledger schema `evidence/runs/RUN-schema.json`; artifacts carry canonical hashes;
  the verifier re-hashes every indexed artifact.
- VM snapshot before each run; cleanup probe + process list after; secrets never in
  ledgers, logs, exports or receipts (env-only).

## References

- `attack-chain-plan.md` — stage design, boundaries, gates.
- `correlation-architecture.md` — joins, tiers, sensor/ingest checklist.
- `config/sysmon-config.xml` — telemetry configuration.