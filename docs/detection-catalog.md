# Detection catalog

The source of truth for query behavior is [rules_wmi.ndjson](../rules/rules_wmi.ndjson). Queries, rule IDs, schedules, and severity values are retained during the documentation refresh. Rule descriptions and notes have been aligned with their actual scope.

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

## Interpretation rules

- Treat a signal as a lead requiring context, not a confirmed incident.
- C2–C5 currently join by `host.name`. Review process identities, ancestry, object references, and file paths before assigning causality.
- Validate actual ECS and raw Sysmon fields before changing joins. Parent and child processes have distinct identities.
- Do not treat a vendor-like subscription name as proof of trusted provenance.
- The scenario uses curl for file transmission and PowerShell for notifications. Attribute C4/C5 alerts to their source events before claiming they detect file transmission.
- C5 has a two-minute lookback and a two-minute maximum sequence span. Test scheduler boundaries and measured ingestion delays; the configuration does not guarantee complete boundary coverage.

## Notification packaging

The public export contains no action connectors or rule actions. Configure notifications privately after rule validation. Historical embedded response commands have been removed. Notes point to the case study and state that response is untested. Query semantics remain unchanged.

## References

- [Microsoft Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Elastic EQL syntax](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax)
- [Elastic detection rule troubleshooting](https://www.elastic.co/docs/troubleshoot/security/detection-rules)
