# WMI Persistence: Execution Evidence and Elastic Detections

A Windows lab investigating a local intrusion scenario through **WMI subscription events, process activity, file operations, and Elastic alerts**.

The scenario combines script execution, a Fodhelper-based UAC bypass attempt, WMI persistence, discovery, local collection, ZIP archiving, web-service transmission, and cleanup. The engineering question is how much of that story can be established from the collected evidence.

**Windows · Sysmon · Elastic Agent · Elasticsearch/Kibana · EQL**

## Results at a glance

- Nine EQL rules: **four sequences and five single-event detections**.
- Historical screenshot evidence includes WMI binding creation, discovery process execution, staging/ZIP creation, curl network activity, ZIP deletion, and **10 alerts across the nine rules**.
- Raw event exports and source-event references for every alert are not yet published. Detection accuracy and latency have not been measured against a labeled baseline.

![Historical Elastic alert overview](docs/evidence/alerts-overview.png)

The screenshot records alerts observed in April 2026. It is not evidence of ten distinct incidents or nine independently validated techniques. Exported suppression settings can group matching results. Current rule titles have been corrected; screenshots retain the historical names.

## Attack-to-detection mapping

The table connects the scenario's behavior to the telemetry used by the implemented rules. The retained alert overview contains a result for every listed rule; evidence details are in the [full mapping](docs/attack-detection-mapping.md).

| Scenario behavior | Telemetry used by detection | Implemented rules | Recorded result |
| --- | --- | --- | --- |
| Fodhelper-related interpreter launch — T1548.002 | Process creation and parent executable | **C1** | Alert for wscript with Fodhelper parent |
| VBScript and PowerShell execution — T1059.005/.001 | Script-host parentage and PowerShell command-line patterns | **S1, S2** | Script-host and PowerShell alerts |
| WMI subscription installation — T1546.003 | WMI filter, consumer, and binding creation: IDs 19/20/21 | **C2** | Binding screenshot and sequence alert |
| WMI-launched execution and discovery — T1546.003, T1082/T1016 | WMI-parented PowerShell and discovery-process events | **S3, C3** | WMI-parented PowerShell alert, ARP event, and sequence alert |
| Local staging and ZIP creation — T1005, T1074.001, T1560.001 | PowerShell file creation: ID 11 | **C4**, file stages | Manifest and ZIP creation screenshots; C4 alert |
| Outbound web-service activity — T1567 | Process-attributed network connections: ID 3 | **S4**; PowerShell network stages in **C4/C5** | Separate S4 alerts for curl and PowerShell |
| Archive deletion — T1070.004 | File deletion: ID 23, after an outbound event | **C5** | ZIP deletion screenshot and sequence alert |

C4/C5 select PowerShell network events, while the archive-transmission code uses curl. Their alerts therefore require source-event attribution before they can be described as detection of the archive transfer itself. ATT&CK labels describe the analyzed behaviors, not independently validated technique coverage.

## Read the analysis

1. **[Attack-to-detection mapping](docs/attack-detection-mapping.md)** — what was implemented on each side, the connecting fields, and the recorded alerts.
2. **[Case study and evidence](docs/case-study.md)** — partial UTC timeline, telemetry assessment, and original screenshots.
3. **[Scenario analysis](docs/scenario-analysis.md)** — the behaviors present in the original code.
4. **[Detection catalog](docs/detection-catalog.md)** — the exact scope and current title of each exported query.
5. **[Telemetry contract](docs/telemetry-contract.md)** — field dependencies, event semantics, scheduling and suppression.

## Repository structure

| Location | Purpose |
| --- | --- |
| `scripts/` | Original scenario code and a static source map |
| `phishing/` | Original delivery-page artifact |
| `config/` | Sysmon telemetry configuration |
| `rules/` | Public detection export without notification credentials/actions |
| `docs/` | Case study, scenario analysis, attack-to-detection mapping, and detection catalog |
| `docs/evidence/` | Selected original screenshots and their provenance/hashes |
| `tools/` | Offline repository validator |
| `.github/workflows/` | Validation workflow |

Sysmon events flow through Windows Event Log and Elastic Agent into Elasticsearch; Kibana evaluates the rules. Fleet manages the agent policy. Notification connectors belong in the private destination environment.

## Offline checks

With Python 3.9+:

```sh
python tools/validate_repository.py
```

The validator checks configuration syntax, rule inventory, metadata consistency, export hygiene, evidence hashes, and local documentation links. It does not execute the scenario, validate Windows behavior, or compile EQL. See the [change record](CHANGELOG.md) for the refresh scope.

## Evidence scope

The published material documents the implemented scenario and observed alerts. Full source-event attribution and a labeled benign baseline are not included, so no detection-accuracy or complete end-to-end validation claim is made.

The original connector export exposed a credential. It has been removed from the current package; owner-side revocation and historical exposure review remain necessary.
