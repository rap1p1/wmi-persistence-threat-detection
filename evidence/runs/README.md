# Run records

[Evidence model](../README.md) · [Run reports](../../reports/README.md) · [Ledger schema](RUN-schema.json)

## Retained runs

| Run | Ledger | Findings |
|---|---|---|
| **RUN-20261003-04** | [Ledger](RUN-20261003-04/RUN-20261003-04.json) | [Latest report](../../reports/reference-run-20261003-04.md): Medium-to-High evidence, finalised receipt and separate AV-off reboot check; executed 4 October |
| RUN-20261003-03 | [Ledger](RUN-20261003-03/RUN-20261003-03.json) | [Report](../../reports/reference-run-20261003-03.md): live alerts and per-rule cluster comparison |
| RUN-20261003-02 | [Ledger](RUN-20261003-02/RUN-20261003-02.json) | [Report](../../reports/reference-run-20261003-02.md): live-alert run and entity-based E3 ownership |
| RUN-20261003-01 | [Ledger](RUN-20261003-01/RUN-20261003-01.json) | [Report](../../reports/reference-run-20261003-01.md): initial query-level verification |

## RUN-04 evidence entry points

| Assertion | Record |
|---|---|
| Starting and resulting integrity | [Before](RUN-20261003-04/elevation-before.json), [after](RUN-20261003-04/elevation-after.json) |
| Installed consumer measurement | [Guest hash probe](RUN-20261003-04/probe-svhw-hash.json) |
| Received archive and manifest context | [ART-07-01 receipt](RUN-20261003-04/ART-07-01-RUN-20261003-04.json), [manifest snapshot](RUN-20261003-04/_manifest.txt) |
| Stored rule alerts | [Alert manifest](RUN-20261003-04/alert-manifest.json) |
| Archive/staging cleanup | [ART-08-01](RUN-20261003-04/ART-08-01-RUN-20261003-04.json) |
| Later AV-off reboot experiment | [Reboot survival record](RUN-20261003-04/reboot-survival.json) |

## Ledger and artifact conventions

- Preserve real Elasticsearch IDs, UTC timestamps, event codes, host and join fields.
- Preserve stage status and explicit missing-evidence notes. Overall acceptance does not erase a sensor gap.
- Text artifact hashes use CRLF-to-LF normalization; binary hashes use raw bytes.
- Guest consumer-file hashes are separately measured. E11 does not supply that script-content hash on this stack.
- Run-scoped prepared payloads stay under each run's `payload/` folder and remain indexed as artifacts.
- ZIP bytes are gitignored; a clone contains the transfer receipt, not the original transferred archive.
- Verify run identity inside artifacts, not only their directory name. Credentials are runtime inputs.

The [April screenshots](../sanitized-screenshots/README.md) are historical material
and must not be used to substantiate an October run. See the [validation guide](../../docs/validation/README.md)
and existing [operator runbook](../../scripts/runbooks/README.md) for evaluation context.
