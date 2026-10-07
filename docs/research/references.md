# Source register and citation conventions

[Reading guide](../README.md) · [Research overview](overview.md)

| ID | Source | Role in this study |
|---|---|---|
| W1 | [Microsoft, How User Account Control works](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works) | Account, token and elevation context. |
| W2 | [MITRE ATT&CK, Bypass User Account Control — T1548.002](https://attack.mitre.org/techniques/T1548/002/) | Technique vocabulary; a tag alone does not prove elevation. |
| W3 | [MITRE ATT&CK, WMI Event Subscription — T1546.003](https://attack.mitre.org/techniques/T1546/003/) | Registration/persistence mechanism and detection context. |
| W4 | [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Event semantics and documented sensor behavior. |
| W5 | [Elastic EQL syntax](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax) | Query and sequence semantics. |
| W6 | [Elastic alert suppression](https://www.elastic.co/docs/solutions/security/detect-and-alert/alert-suppression) | Operational interpretation of grouping and alert counts. |
| L1 | [Run reports](../../reports/README.md) and [run evidence](../../evidence/runs/README.md) | Recorded laboratory observations and their provenance. |
| L2 | [Rule catalogue/export](../../detections/README.md) | Detection basis, including the rule-level references carried in exported metadata. |

## Citation and claim rules

Distinguish source-backed mechanism descriptions, implemented code, run observations and analyst inference. Cite a specific run and event or measurement for empirical claims. In particular:

- Do not treat the April screenshot dataset as evidence for an October run.
- Preserve the difference between guest-probe file hashes and event-native fields.
- Preserve the before/after measurement caveat; SYSTEM consumer execution and a Medium-to-High transition are separate assertions.
- A receipt binds the observed byte set to its recorded run/host context and token-holder contract; it does not cryptographically identify the victim.
- Rule-specific ATT&CK/Sigma references explain detection design. They do not make a laboratory predicate universally validated.

## Revision context

The documentation reorganization was based on upstream commit **`9c3238964a0c40997e3661ab21df4f82b39bac9a`**, including RUN-20261003-04. Recorded software versions belong to the run context; mutable external links are not version pins. This edit reconciles retained sources and evidence and does not represent a new live experiment.
