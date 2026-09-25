# WMI Persistence: Execution Evidence and Elastic Detections

A Windows lab investigating a local intrusion scenario through **WMI subscription events, process activity, file operations, and Elastic alerts**.

The scenario combines script execution, a Fodhelper-based UAC bypass attempt, WMI persistence, discovery, local collection, ZIP archiving, web-service transmission, and cleanup. The engineering question is how much of that story can be established from the collected evidence.

**Windows · Sysmon · Elastic Agent · Elasticsearch/Kibana · EQL**

## Results at a glance

- Nine EQL rules: **four sequences and five single-event detections**.
- Historical screenshot evidence includes WMI binding creation, discovery process execution, staging/ZIP creation, curl network activity, ZIP deletion, and **10 alerts across the nine rules**.
- Raw event exports and source-event references for every alert are not yet published. Detection accuracy and latency have not been measured against a labeled baseline.
- Incident response and a response playbook have **not been implemented or tested** in this project.

![Historical Elastic alert overview](docs/evidence/alerts-overview.png)

The screenshot records alerts observed in April 2026. It is not evidence of ten distinct incidents or nine independently validated techniques.

## Techniques represented in the existing code

| Behavior | Implementation observed in the repository | Evidence scope |
| --- | --- | --- |
| Script execution — T1059.003/.005/.001 | Batch launcher, temporary VBScript, and PowerShell; PowerShell also contains the later WMI-consumer script | Process/alert evidence exists; a complete process tree is not published |
| UAC bypass attempt — T1548.002 | Fodhelper-related per-user registry modification and interpreter launch | C1 observes a child process; the before/after privilege transition needs separate evidence |
| WMI event subscription — T1546.003 | Filter, command-line consumer, and binding refer to a local process-start condition and an on-disk script | Binding screenshot and C2/S3 alerts; reboot survival not demonstrated |
| Discovery — T1082, T1016, T1087.001 | OS, network configuration, ARP cache, and local-account enumeration | ARP process screenshot; the other queries are code-observed, not individually proven by that event |
| Local collection and staging — T1005, T1074.001 | User-folder files and shell-history files are selected and placed in a temporary staging directory | Selected file event shows the generated manifest; source-file provenance is not demonstrated |
| Archive collected data — T1560.001 | PowerShell ZIP creation | ZIP file creation shown; archive contents/hashes not published |
| Web-service transmission — T1567, analytical mapping | curl sends the archive; PowerShell sends status/error messages to Telegram | curl connection shown; C4/C5 instead filter for PowerShell network events |
| File deletion — T1070.004 | Cleanup includes staging/archive deletion and a history-clearing operation | ZIP deletion shown; this does not prove every cleanup operation completed |

[Scenario analysis](docs/scenario-analysis.md) explains these behaviors, original-code boundaries, and ATT&CK mapping qualifications. No credential dumping, lateral movement, or injection is demonstrated by this repository. Initial delivery remains scenario context, not a validated phishing detection.

## Read the case study

1. **[Case study and evidence](docs/case-study.md)** — observations, timeline, telemetry coverage, and unresolved conclusions.
2. **[Detection catalog](docs/detection-catalog.md)** — exact query scope and rule limitations.
3. **[Validation plan](docs/validation-plan.md)** — the next experiments, explicitly marked as planned work.
4. **[Run record template](docs/templates/run-record.md)** — a blank record for future measurements.

## Repository structure

| Location | Purpose |
| --- | --- |
| `scripts/` | Original scenario code and a static source map |
| `phishing/` | Original delivery-page artifact |
| `config/` | Sysmon telemetry configuration |
| `rules/` | Public detection export without notification credentials/actions |
| `docs/` | Markdown case study, analysis, detection catalog, and planned validation |
| `docs/evidence/` | Selected original screenshots and their provenance/hashes |
| `tools/` | Offline repository validator |
| `.github/workflows/` | Validation workflow |

Sysmon events flow through Windows Event Log and Elastic Agent into Elasticsearch; Kibana evaluates the rules. Fleet manages the agent policy. Notification connectors belong in the private destination environment.

## Offline checks

With Python 3.9+:

```sh
python tools/validate_repository.py
```

The validator checks configuration syntax, rule inventory, export hygiene, evidence hashes, and local documentation links. It does not execute the scenario, validate Windows behavior, or compile EQL. See the [change record](CHANGELOG.md) for the refresh scope.

## Current priorities

Establish source-event attribution for C4/C5, replace host-only correlation assumptions with verified entity relationships, and publish a sanitized raw-event run with negative cases. These are validation tasks; adding more technique names would not resolve them.

The original connector export exposed a credential. It has been removed from the current package; owner-side revocation and historical exposure review remain necessary.
