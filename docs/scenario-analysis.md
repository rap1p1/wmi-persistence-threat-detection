# Scenario analysis

This is a static description of existing artifacts and an evidence map, not an execution guide. “Present in code” means the behavior is implemented or attempted; it does not establish successful execution.

## Source organization

| Artifact | Responsibility | Review boundary |
| --- | --- | --- |
| `phishing/landing_page.html` | Delivery-themed page | The page alone does not prove delivery, download, or user execution |
| `scripts/setup.bat` | Launcher and privilege-related setup | References an optional `setup.hta` that is not in the repository |
| `scripts/payload.ps1`, outer script | Writes a separate consumer script and manages a named WMI subscription | Installation and subsequent activation are different events |
| `scripts/payload.ps1`, embedded script | Discovery, collection, staging, archiving, transmission, and cleanup | Embedded code is not executed merely because the outer file contains it |

The scripts remain at their original paths with unchanged bytes. The distinction between launcher, installer, and embedded consumer clarifies which process and event should be attributed to each responsibility. See the [source map](../scripts/README.md).

## Execution and privilege context

The launcher uses native Windows script hosts and PowerShell. It includes per-user registry changes associated with a Fodhelper-based UAC bypass attempt. This is represented by T1059.003, T1059.005, T1059.001, and T1548.002.

C1 detects an interpreter with Fodhelper as parent. It does not verify the registry stage or the resulting token. The correct evidence question is whether the initial account was a local administrator with a filtered token and what integrity/security context the resulting process actually had. “Standard user became administrator” is not an established finding.

## WMI persistence

The outer PowerShell script creates a filter, command-line consumer, and binding. The event condition concerns a local process starting; the consumer references a script stored on disk. This is WMI event-subscription behavior (T1546.003).

The recorded binding references named filter and consumer objects. Activation, installation, persistence across reboot, and removal are separate assertions. The screenshots do not demonstrate a reboot-survival test. The on-disk script means the scenario is not wholly fileless.

## Discovery

The embedded script queries the operating system, network addresses, local accounts, and ARP cache. The applicable analytical categories are system information discovery (T1082), network configuration discovery (T1016), and local account discovery (T1087.001).

A screenshot proves that `ARP.EXE` started. It does not individually prove the results of the PowerShell-based queries. The published evidence does not include the relevant script telemetry and sanitized query output associated with that process identity.

## Collection and staging

The code selects files from user folders and copies shell-history files into a temporary staging directory, then writes a manifest. This supports code-level mapping to local data collection (T1005) and local staging (T1074.001). The source list is broader than a dedicated synthetic dataset.

The selected Event ID 11 screenshot shows `_manifest.txt`. That supports manifest creation, not successful collection of all candidate documents. File counts, extensions, or a script's summary are not independent evidence of which source contents were collected. Reading shell history also does not prove credential discovery or theft; no credential-extraction result is demonstrated here.

## Archive and network activity

PowerShell creates a ZIP archive (T1560.001). The embedded script assigns archive transmission to curl and status/error notifications to PowerShell. A later notification is not equivalent to a successful archive transfer.

The behavior is analyzed here as web-service transmission (T1567). The historical rules retain their original T1041 tags for traceability, but the repository does not demonstrate an established interactive C2 channel. The mapping remains separate from proof of transfer success.

The curl network event and the PowerShell network stages in C4/C5 refer to different process roles. Alert-source events are needed to determine precisely what each sequence matched. This discrepancy is a substantive detection-engineering finding.

## Cleanup

The code attempts staging/archive deletion and clearing of the current execution context's history file. The retained Event ID 23 screenshot establishes ZIP deletion by `cmd.exe`, supporting T1070.004 for that observed artifact.

It does not show that all copied histories, the installed consumer script, or the WMI subscription were removed. Deletion does not establish why it occurred or that a previous transfer succeeded. Broad cleanup claims from the former report are not carried forward.

## Delivery context and absent techniques

A landing page and a narrative about packaged delivery are present, but the full delivery-to-execution evidence is not published. Treat phishing/user-execution labels as context unless supporting browser, download, and process evidence is added.

The repository does not implement a demonstrated credential-dumping, remote lateral-movement, injection, or ransomware-impact stage. This is a local WMI-centered scenario; it should be evaluated on that scope.

## Detection mapping

See [attack-to-detection mapping](attack-detection-mapping.md) for how these behaviors relate to the implemented rules and retained evidence.

## References

- [MITRE ATT&CK: WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)
- [MITRE ATT&CK: Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567/)
- [MITRE ATT&CK Enterprise techniques](https://attack.mitre.org/techniques/enterprise/)
- [Microsoft Sysmon event definitions](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
