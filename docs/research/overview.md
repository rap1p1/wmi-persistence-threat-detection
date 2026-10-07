# Research overview and foundations

[Reading guide](../README.md) · Next: [laboratory architecture](../lab/architecture.md)

## Research objective

Determine which observations distinguish privilege-related activity, WMI subscription registration, consumer execution, file transfer and cleanup in one Windows endpoint scenario, and evaluate how much of that chain the committed EQL rules and evidence verifier can support.

## Research questions

| Question | Required evidence | Current reference |
|---|---|---|
| RQ1. Is a Medium-to-High transition observed? | Before/after integrity measurements and corroborating process context, with the starting account's privilege model stated. | RUN-04 report and elevation measurements |
| RQ2. Are registration, activation and reboot survival individually supported? | E19/20/21 object references; consumer parent/user context; separate post-reboot state and execution observations. | RUN-04 ledger and attached AV-off reboot check |
| RQ3. Which links are expressed by detection logic versus separately verified? | Query predicates, join keys, exported schedule and verifier assertions. | [Catalogue](../../detections/README.md), [correlation model](../detection/correlation.md) |
| RQ4. Does upload intent correspond to received data? | E1/E3 process ownership where available, guest manifest and server receipt. | RUN-04 receipt; explicit entity-attribution gaps |

## Windows concepts used in the analysis

**UAC and integrity.** A local administrator can start with a filtered token. Account membership, the token used by a process, integrity level and SYSTEM execution are distinct observations. RUN-04 records a filtered-administrator Medium-to-High transition; it does not demonstrate an unprivileged standard account becoming an administrator. The recorded measurements use mandatory labels, with their probe caveat retained. [W1, W2](references.md)

**WMI permanent subscriptions.** The filter defines a condition, the consumer an action and the binding connects them. Registration telemetry supports object creation. Consumer execution needs process evidence; survival across restart needs a separate reboot experiment. RUN-04's AV-off reboot evidence is outside its main 08:15–08:23 UTC window. [W3](references.md)

**Event semantics.** Sysmon E1 is process creation; E3 is connection telemetry; E11 is file creation; E19/20/21 cover WMI subscription objects; E23 records file deletion with archiving. These records have different evidential scopes. An E11 image hash must not be presented as a measured script-content hash. [W4](references.md)

**Correlation and detection.** Same-host process identity can connect parent/child or process/network events. C3 uses an asymmetric entity-to-parent join; C5 joins the same file path. C2/R2 supply host/time candidates, while the verifier checks the recorded WMI object references. The strongest justified claim depends on the actual available key. [Correlation design](../detection/correlation.md)

## Study design and contribution

Four retained runs document successive development and validation contexts. Runs 01–03 began at High integrity; RUN-04 began at Medium integrity and includes three consumer activations, an initial failed upload and a separate reboot check. Compare them as development iterations, not equivalent trials.

The contribution is a reproducible evidence model that distinguishes registration from execution, upload intent from receipt, and stored alert volume from unique activity. Historical April screenshots remain an earlier dataset in the [archive](../archive/README.md). The current study does not establish production precision/recall, AV-on reboot survival, remote lateral movement or an end-to-end delivery chain.
