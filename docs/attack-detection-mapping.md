# Attack-to-detection mapping

This document connects the behaviors in the original scenario code to the detection engineering implemented in the repository. The [rule export](../rules/rules_wmi.ndjson) defines query behavior; the [retained screenshots](case-study.md#selected-evidence) show the recorded results.

## Coverage map

| Scenario behavior and code location | Detection work implemented | Telemetry and fields used | Recorded evidence | Interpretation |
| --- | --- | --- | --- | --- |
| **Privilege-related interpreter launch** in `setup.bat` — T1548.002 | **C1** selects an interpreter whose parent is Fodhelper | Sysmon **1**; `process.parent.name`, `process.name` | [E07](case-study.md#e07--alert-overview): C1 reason identifies wscript with Fodhelper parent | Detects the process relationship; query does not establish a registry sequence or token elevation |
| **VBScript execution** in the launcher — T1059.005 | **S1** selects wscript/cscript under Fodhelper or cmd | Sysmon **1**; process name and parent name | [E07](case-study.md#e07--alert-overview): S1 alert | Detects the script host itself; it does not require a PowerShell child |
| **PowerShell execution** of the scenario script — T1059.001 | **S2** matches hidden plus bypass/encoded command-line patterns, with parent exclusions | Sysmon **1**; `process.command_line` or raw `CommandLine`, process/parent names | [E07](case-study.md#e07--alert-overview): S2 reason identifies PowerShell with wscript parent | A command-line/context signal rather than proof of script contents |
| **WMI subscription installation** in the outer PowerShell script — T1546.003 | **C2** sequences filter, consumer, and binding creation within 30 seconds | Sysmon **19 → 20 → 21**; host name, event ID, operation, object name | [E01](case-study.md#e01--wmi-object-binding): named binding; [E07](case-study.md#e07--alert-overview): C2 alert | Current query joins by host/time; it does not match the binding references to the selected filter/consumer events |
| **WMI-launched interpreter execution** associated with the consumer — T1546.003 / T1059.001 | **S3** selects listed shells/tools under WmiPrvSE or scrcons in SYSTEM context | Sysmon **1**; process/parent name or parent path, user name | [E07](case-study.md#e07--alert-overview): S3 reason identifies WmiPrvSE-parented PowerShell | Process-context evidence; connecting it to the exact subscription requires underlying event attribution |
| **Discovery after WMI-launched execution** in the embedded script — T1082 / T1016 | **C3** sequences WMI-parented SYSTEM PowerShell and a listed SYSTEM discovery process within 30 seconds | Sysmon **1 → 1**; host, process/parent, user, command line | [E02](case-study.md#e02--discovery-process): ARP process; [E07](case-study.md#e07--alert-overview): C3 alert | Covers the selected discovery-process pattern; does not prove all in-process OS/network/account queries |
| **Local staging and ZIP creation** in the embedded script — T1005 / T1074.001 / T1560.001 | **C4** begins with non-excluded staging file creation and ZIP creation, then requires a PowerShell outbound event within two minutes | Sysmon **11 → 11 → 3**; file path/extension, process, user, destination, host | [E03](case-study.md#e03--staging-manifest): manifest; [E04](case-study.md#e04--archive-creation): ZIP; [E07](case-study.md#e07--alert-overview): C4 alert | Shows file activity and a sequence alert; the screenshot does not identify which source documents were collected |
| **Archive transmission and separate status messages** in the embedded script — T1567 analytical mapping | **S4** selects SYSTEM curl/PowerShell outbound connections on configured web ports, outside excluded address ranges | Sysmon **3**; process name, user, destination IP/port | [E05](case-study.md#e05--network-activity): curl connection; [E07](case-study.md#e07--alert-overview): one curl S4 and one PowerShell S4 | Detects both process roles; connection metadata alone does not prove successful file receipt |
| **Archive cleanup** in the embedded script — T1070.004 | **C5** sequences a SYSTEM PowerShell outbound event and qualifying file deletion within 120 seconds | Sysmon **3 → 23**; host, user, process, destination, file path/extension | [E06](case-study.md#e06--archive-deletion): ZIP deleted by cmd; [E07](case-study.md#e07--alert-overview): C5 alert | Detects the configured temporal pattern; it does not establish that the deleted file was successfully transferred |

## How the detection layers relate

The rules cover three connected areas of the scenario:

- **Launcher activity:** C1, S1, and S2 observe process relationships and command-line context. C1 and S1 can overlap on the same process event; their alert count is not a count of independent attack steps.
- **WMI installation and subsequent activity:** C2 observes subscription registration, S3 observes an interpreter under a WMI host, and C3 adds discovery-process activity. Installation and activation have separate evidence.
- **File handling and network activity:** C4 combines staging, archiving, and a connection; S4 provides individual network signals; C5 adds deletion after a connection.

The retained overview shows **10 alerts across nine rules**, including two S4 alerts. Several rules intentionally observe overlapping behavior. The screenshot alone does not establish that every rule used the same underlying run or the specific source events implied by the narrative.

## Event relationships visible in the evidence

The manifest and ZIP file screenshots display the same PowerShell ProcessGuid and PID. That provides a concrete link between those two file events.

The curl connection and cmd deletion screenshots have different process identities. Their parent/child relationships are not displayed in the selected images. C4/C5 currently join by `host.name`, so the query does not supply that missing process relationship.

The binding screenshot explicitly references a filter and a consumer. C2 checks ordered event types on the same host, rather than joining those references. The distinction is between what the telemetry contains and what the current query actually uses.

## Behavior coverage versus rule coverage

| Behavior present in code or scenario context | Relationship to implemented detection |
| --- | --- |
| Batch execution — T1059.003 | Present in the launcher/context; no dedicated batch-execution rule |
| Per-user registry modifications | The configuration includes registry telemetry, but C1 does not consume a registry event |
| Local-account enumeration — T1087.001 | Present in the embedded script; no dedicated rule for that in-process operation |
| Shell-history file collection | Part of collection logic; no dedicated rule or demonstrated credential-extraction result |
| Local staging — T1074.001 | Reflected in C4's path-based file stages; original rule tags are preserved |
| PowerShell status/error messages | Can contribute network signals; must not automatically be labeled archive transmission |
| History-clearing operation | Present in code; the retained deletion evidence specifically identifies the ZIP |
| Delivery page and user execution | Scenario context; no complete delivery-to-execution detection demonstrated |

The scenario analysis uses T1567 for web-service transmission. Historical export tags retain T1041. This documents a mapping distinction without silently changing rule metadata or asserting an established C2 channel.

## Scope of the published result

This mapping documents existing code, existing queries, and retained evidence. It is not a coverage percentage. Full raw source-event exports and a labeled benign baseline are absent, so alert correctness and false-positive rates cannot be derived from the screenshots.

See the [detection catalog](detection-catalog.md) for query limits and the [case study](case-study.md) for the timestamped observations.
