# Telemetry contract and interpretation

The rule export documents fields consumed by query predicates, implicit event categories, timestamps, and suppression. These declarations describe data dependencies; they do not verify the destination mapping or make every fallback field mandatory on every event.

## Source and normalized fields

| Data | Fields used or inspected | Interpretation |
| --- | --- | --- |
| Event selection | `winlog.channel`, `winlog.event_id`, `event.category` | Matching an event ID is insufficient if the EQL category is absent or different. C2 uses `any`; the other rules select process, file or network categories. |
| Time | `@timestamp`, ingestion time, alert creation time | Preserve event time, arrival time and alert time separately. No timestamp override is configured in the export. |
| Process identity | `process.name`, `process.parent.name`, executable paths, raw ProcessGuid/ParentProcessGuid or verified ECS identity | A process name is not an identity. PID can be reused; parent and child have different identities. |
| Execution context | Event-specific user fields, integrity/token context | The Event Viewer summary User field is not interchangeable with EventData.User. In the binding screenshot, these represent different accounts. Account membership, effective token and integrity level are distinct. |
| WMI objects | Event types 19/20/21; object names and binding references | Registration, binding, activation and survival across reboot are different assertions. C2 currently uses host/time rather than object-reference joins. |
| Files | `file.path`, `file.extension`, process identity; independently collected file hashes | Creation of a manifest does not prove collection of source files. ZIP-path creation does not establish contents. A process-image hash is not a script or archive hash. |
| Connections | `destination.ip`, `destination.port`, process identity | Selected web ports do not establish HTTP/HTTPS or successful transfer. Address exclusions are not a complete public-address classifier. |
| Suppression | Exported grouping fields and `kibana.alert.suppression.docs_count` | Counts of original events, sequence matches and representative alerts are different measurements. |

`required_fields` supplies reference types: date for the timestamp, IP for destination.ip, long for destination.port, and searchable string types for names, paths and command lines. An installed integration may use compatible keyword/wildcard mappings. Verify actual mappings and example documents; do not overwrite them from this metadata alone. Event IDs are compared as strings in the current queries.

## Query and field semantics

The current EQL retains its original operators: `==`, `in` and `like` are case-sensitive, while `:` is case-insensitive. Their mixed use is an explicit portability limitation until checked against actual normalized field values. A successful Windows path lookup does not establish EQL string equivalence.

Raw and ECS command-line fields occur as alternatives in some rules. A missing field or a missing parent value can affect predicates and exclusions; absence is not evidence of a benign process. C2 includes a name-based exclusion, not a verified publisher/provenance check. C4/C5 do not enforce process ancestry or file identity across their stages.

## File deletion semantics

Sysmon Event ID 23 records deletion with archiving. Without an explicit ArchiveDirectory, Sysmon uses its default archive location, normally C:\Sysmon. Event ID 26 records deletion without archiving. The checked-in C5 query selects 23, not 26; omitting ArchiveDirectory does not change that behavior. Monitor archive storage and protect retained file contents according to the lab's data handling policy.

Content clearing/truncation is distinct from deleting a file. The displayed ZIP deletion does not establish history clearing, consumer-script removal, or subscription removal. A before/after inventory and event-specific evidence are needed to assert those outcomes.

## Scheduling and suppression

| Rule | Interval | Query start | Sequence span | Suppression group | Duration |
| --- | --- | --- | --- | --- | --- |
| C1 | 1m | `now-2m` | Single event | `host.name` | 30s |
| C2 | 1m | `now-2m` | 30s | `host.name`, `winlog.computer_name` | 30s |
| C3 | 1m | `now-2m` | 30s | `host.name` | 60s |
| C4 | 1m | `now-3m` | 2m | `host.name` | 120s |
| C5 | 1m | `now-2m` | 120s | `host.name` | 30s |
| S1 | 1m | `now-2m` | Single event | `host.name` | 30s |
| S2 | 1m | `now-2m` | Single event | `host.name`, `user.name` | 60s |
| S3 | 1m | `now-2m` | Single event | `host.name` | 60s |
| S4 | 1m | `now-2m` | Single event | `host.name` | 60s |

All rules retain `missing_fields_strategy: suppress` and a maximum of 100 alerts per run. Suppression requires support in the destination subscription and active rule configuration. Missing grouping fields are grouped as null when this strategy applies; inspect the raw events rather than interpreting a single alert as one occurrence. Closing an alert and rule execution limits can also affect the displayed counts.

C5 has a two-minute lookback, two-minute maximum span and a one-minute schedule. This does not establish complete coverage near scheduler boundaries. C4's three-minute lookback is likewise not evidence of tolerance for an arbitrary ingestion delay. Rule execution history, gaps, source timestamps and arrival timestamps are absent from the published evidence, so no latency or full timing-coverage claim is made.

The index patterns are inherited broad Elastic Security defaults. Channel filtering narrows candidate documents but does not prove all indices have compatible mappings. The repository validator does not connect to Elasticsearch or compile EQL.

## Historical evidence and current names

Rule titles have been narrowed to the event patterns actually selected. The C1-C5/S1-S4 prefixes and rule_id values are retained. Screenshots show the historical names; their labels and severity values are not fresh measurements of the updated metadata. Query predicates, schedules, suppression, severity and ATT&CK tags remain unchanged; query comments have been corrected. Metadata versions were incremented.

## References

- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft UAC](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
- [Elastic EQL syntax](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax)
- [Elastic alert suppression](https://www.elastic.co/docs/solutions/security/detect-and-alert/alert-suppression)
