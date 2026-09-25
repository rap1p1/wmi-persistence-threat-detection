# Validation plan — proposed, not executed

All cases below are NOT RUN in this documentation refresh. The project has no implemented or tested incident-response playbook.

The purpose is to establish which behavior happened, which telemetry recorded it, which query matched, and whether the alert conclusion is supported.

## 1. Establish the environment

Record OS build, account context, Sysmon version/schema, active configuration hash, Elastic/Agent versions, policy, index patterns, and rule revision. Confirm clocks and document time zones. Historical version strings alone are not a reproduced environment.

Run the offline repository validator. In the lab, separately verify configuration acceptance, event delivery, field types, rule import, and EQL execution. Mark missing prerequisites as blocked rather than passed.

## 2. Collect evidence for each run

Use the [run record](templates/run-record.md). Limit experimental file activity to designated synthetic fixtures and a controlled receiver. Keep a manifest of fixture names and hashes. Record outcomes independently of the alerting system.

Save sanitized raw events and alert source-event references. Keep event time, ingestion time, alert creation time, and notification time distinct. Preserve process GUID/entity identity where available; PID alone can be reused.

Live tests validate actual telemetry and ingestion. Replay of captured events provides repeatable query regression tests but does not validate the live collection pipeline.

## 3. Required cases

| Case | Experiment question | Expected evaluation |
| --- | --- | --- |
| V01 | Does an existing harmless test subscription's marker activation have the expected WMI/process evidence? | Verify exact object references and marker outcome; missing telemetry blocks the conclusion |
| V02 | Does approved WMI administration generate similar signals? | Document legitimate context and any alerts; do not assume zero false positives |
| V03 | Can independent same-host events be incorrectly joined? | Unrelated events must not be reported as a proven causal chain; current queries may expose this gap |
| V04 | Are synthetic-file transfer and status notification distinguishable? | Attribute every alert to the correct process/events and independently confirm receiver receipt |
| V05 | What happens when a required event is missing or arrives late? | Record the telemetry gap or timing failure; absence of an alert is not a passing result |
| V06 | Does targeted remediation stop the test marker without affecting approved objects? | Preserve pre-change evidence; verify the target and unaffected baseline after response |

This plan specifies defensive acceptance criteria. It does not automate creation or execution of the historical scenario chain.

## 4. Report outcomes honestly

- **PASS:** Required evidence is complete and the observed result meets the predefined expectation.
- **FAIL:** Evidence is sufficient and demonstrates a mismatch.
- **BLOCKED:** Missing telemetry, environment access, or prerequisites prevent evaluation.
- **NOT RUN:** No result has been collected.

For labeled positive cases, report TP and FN counts and the tested behaviors. For predefined negative cases, report FP and TN counts with the unit of evaluation. Report alert volume per host-hour separately. Do not turn an arbitrary number of benign events into a misleading false-positive denominator.

Report latency from observed timestamps with the sample count. Rule interval alone is not latency. Separate historical screenshot evidence from newly measured results.

## 5. Publish reproducible evidence

Publish only sanitized exports after reviewing account names, destinations, secrets, file contents, and document images. Keep a manifest of the published evidence with hashes and the matching rule/configuration revision. Do not publish runtime credentials or raw collected user data.
