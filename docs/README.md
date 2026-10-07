# Technical reading guide

Read the study in this order to connect Windows mechanisms, laboratory observations and detection claims.

| Chapter | Read | Supporting material |
|---|---|---|
| 1. Research question and foundations | [Research overview](research/overview.md) | [Source register](research/references.md) |
| 2. Laboratory method | [Architecture](lab/architecture.md) | [Stage design](lab/stage-design.md), [Sysmon config](../config/sysmon-config.xml) |
| 3. Execution and observations | [RUN-04 report](../reports/reference-run-20261003-04.md) | [Ledger](../evidence/runs/RUN-20261003-04/RUN-20261003-04.json), [run/artifact index](../evidence/runs/README.md) |
| 4. Detection engineering | [Rule catalogue](../detections/README.md) | [Correlation model](detection/correlation.md), [telemetry contract](detection/telemetry-contract.md) |
| 5. Evaluation and limitations | [Validation guide](validation/README.md) | [All run reports](../reports/README.md), [reboot evidence](../evidence/runs/RUN-20261003-04/reboot-survival.json) |
| Appendix. Earlier evidence and reviews | [Historical archive](archive/README.md) | April screenshots and dated review context |

## Evidence conventions

- Treat scenario **stages S1–S7** separately from **rule IDs C1–C5, S1–S4 and R1–R2**.
- A rule match, a verifier assertion, an operator measurement and a historical screenshot are different evidence types.
- RUN-04 is the current execution reference. RUN-03 remains useful for its published per-rule cluster comparison; its counts do not describe RUN-04.
- Design documents specify intended behavior. Current findings are bounded by each report's actual run context.

The former flat `docs/*.md` paths remain as compatibility entry points for existing links and exported rule metadata. Canonical content is maintained in the topic folders above.
