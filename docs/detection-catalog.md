# Detection catalog

The source of truth for query behavior is [rules_wmi.ndjson](../rules/rules_wmi.ndjson). Query predicates, rule IDs, schedules, suppression and severity values are retained. Names, comments, setup guidance, descriptions and field metadata now describe the observed patterns without asserting a confirmed incident.

All nine rules are configured to evaluate every minute. A schedule is not a measured time to detect. The export preserves its existing enabled state; review that state in the destination environment before import.

| ID | Actual query type | Observed condition | Limitation |
| --- | --- | --- | --- |
| C1 | Single process event | Fodhelper is the parent of a listed shell/interpreter | No registry-to-process sequence; does not prove privilege elevation |
| C2 | Sequence, 30 seconds | WMI creation events 19, 20, and 21 on the same host | Does not verify that the binding references the observed filter and consumer; name exclusions need review |
| C3 | Sequence, 30 seconds | WMI-parented SYSTEM PowerShell with selected flags, followed by a listed SYSTEM discovery process | Host/time join does not prove process ancestry; no file-staging fallback in this query |
| C4 | Sequence, 2 minutes | PowerShell file creation in staging paths, ZIP creation, then SYSTEM PowerShell outbound connection | No file-to-network attribution or transfer-success evidence; network stage does not match curl |
| C5 | Sequence, 120 seconds | SYSTEM PowerShell outbound connection followed by qualifying SYSTEM file deletion | Does not prove transfer success or that the deleted file was transferred; network stage does not match curl |
| S1 | Single process event | wscript/cscript with fodhelper/cmd parent | Does not require a PowerShell child |
| S2 | Single process event | PowerShell with selected hidden and bypass/encoded flags, subject to exclusions | Narrow flag pattern; not coverage of all PowerShell execution |
| S3 | Single process event | Listed shell/tool under WmiPrvSE/scrcons in SYSTEM context | Parent/context alone does not establish a permanent malicious subscription |
| S4 | Single network event | SYSTEM PowerShell or curl connection to selected web ports, outside listed network ranges | Connection metadata does not prove HTTP, HTTPS, maliciousness, or file transfer |

See the [attack-to-detection mapping](attack-detection-mapping.md) for the scenario context and recorded result of each rule.

## Current titles

Historical screenshots retain their original titles. Prefixes and rule_id values identify the same rules across the metadata update.

| ID | Current title |
| --- | --- |
| C1 | Fodhelper Child Interpreter |
| C2 | WMI Subscription Registration Sequence |
| C3 | WMI-Parented PowerShell Followed by Discovery Process |
| C4 | PowerShell Staging Files, ZIP Creation and Network Activity |
| C5 | SYSTEM PowerShell Network Activity Followed by File Deletion |
| S1 | Script Host With Fodhelper or Cmd Parent |
| S2 | PowerShell Hidden and Bypass or Encoded Command Patterns |
| S3 | SYSTEM Shell or Tool With WMI Host Parent |
| S4 | SYSTEM PowerShell or Curl Network Activity on Web Ports |

See [telemetry contract](telemetry-contract.md) for fields, context interpretation, scheduling and suppression.

## Interpretation rules

- Treat a signal as a lead requiring context, not a confirmed incident.
- C2–C5 currently join by `host.name`. Review process identities, ancestry, object references, and file paths before assigning causality.
- Validate actual ECS and raw Sysmon fields before changing joins. Parent and child processes have distinct identities.
- Do not treat a vendor-like subscription name as proof of trusted provenance.
- The scenario uses curl for file transmission and PowerShell for notifications. Attribute C4/C5 alerts to their source events before claiming they detect file transmission.
- C5 has a two-minute lookback and a two-minute maximum sequence span. Test scheduler boundaries and measured ingestion delays; the configuration does not guarantee complete boundary coverage.

## Notification packaging

The public export contains no action connectors or rule actions. Configure notifications privately after rule validation. Historical embedded response commands have been removed. Setup and notes identify data dependencies and interpretation limits. No implemented response playbook is distributed. Query predicates remain unchanged.

## References

- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Elastic EQL syntax](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax)
- [Elastic detection rule troubleshooting](https://www.elastic.co/docs/troubleshoot/security/detection-rules)
