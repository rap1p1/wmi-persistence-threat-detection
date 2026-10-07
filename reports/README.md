# Run reports

[Reading guide](../docs/README.md) · [Evidence index](../evidence/runs/README.md)

**RUN-20261003-04 is the latest execution reference.** Its identifier retains the
20261003 date prefix, but the run was executed on **4 October 2026**. The reboot
check is attached evidence outside the main run window.

| Run | Observation context | Recorded result |
|---|---|---|
| [RUN-04](reference-run-20261003-04.md) | Medium-integrity start; three consumer activations; finalised receipt; separate AV-off reboot test | ACCEPTED (ES-BACKED), 49 refs / 49 documents; 51 stored alerts |
| [RUN-03](reference-run-20261003-03.md) | High-integrity start; live rules and alert manifest | ACCEPTED (ES-BACKED); 14 per-rule clusters / 25 stored alerts |
| [RUN-02](reference-run-20261003-02.md) | High-integrity start; live-alert run; entity-based E3 ownership | Recorded acceptance and live-alert observations |
| [RUN-01](reference-run-20261003-01.md) | High-integrity start; first retained run | Query-level detection evaluation; rules not yet live in its original window |

These are recorded findings under each run's conditions, not fresh live verification
from a repository checkout. Runs 01–03 do not demonstrate a Medium-to-High transition.
Their findings remain useful within their original scope.

## Reading a report

Read context/window → source-event timeline → stage assertions → detection counts →
limitations → cleanup/recovery → linked ledger/artifacts. Distinguish source-event
time from alert/capture time and a main run from a later attached experiment.

Future reports should identify the source revision and tested configuration, use
actual event/alert IDs, state missing evidence and provide explicit denominators for
any metric. See the [validation guide](../docs/validation/README.md).
