# Evidence model and provenance

[Latest report](../reports/reference-run-20261003-04.md) · [Run index](runs/README.md) · [Validation guide](../docs/validation/README.md)

| Evidence | What it supports |
|---|---|
| Run ledger | Stage context, source-event references, technical join fields and indexed artifacts. |
| Guest measurements | Integrity labels or file hashes measured by the operator; these are distinct from event-native fields. |
| Sink receipt | Receiver-observed name/size/hash and manifest context, subject to the token-holder attribution boundary. |
| Alert manifest | Stored rule-alert IDs and times; not a count of unique adversarial behaviors. |
| Reboot record | A separate, dated survival experiment with its AV state and post-boot event reference. |
| [April screenshots](sanitized-screenshots/README.md) | Historical evidence only; not October run acceptance. |

Text artifact hashes use the verifier's CRLF-to-LF convention; binary hashes use raw bytes. Run-scoped prepared payload copies and their indexed hashes are retained as evidence. Transfer ZIP bytes are not committed; the receipt is the committed server-side transfer record.

Keep source-event, capture, alert and analysis times distinguishable. RUN-04's main window closes at 08:23 UTC; its post-boot consumer event at 08:40:21.543 UTC belongs to the attached reboot check.

`ACCEPTED-LEDGER-ONLY` is an offline consistency result. `ACCEPTED (ES-BACKED)` additionally depends on successful source-document retrieval. Neither status supplies a missing experiment, proves production accuracy or overrides a declared sensor gap.
