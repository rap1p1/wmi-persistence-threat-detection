# Validation, findings and limitations

[Reading guide](../README.md) · [Latest run report](../../reports/reference-run-20261003-04.md) · [Evidence index](../../evidence/README.md)

## What each validation layer establishes

| Layer | Method | What it establishes |
|---|---|---|
| Offline component tests | 47 tests in `scripts/tests/test_offline.py` | Rule metadata/query correspondence, schema/hash/receipt checks and selected negative acceptance cases. |
| Repository packaging | `tools/validate_repository.py` | XML, export hygiene, ledgers/receipts, screenshot hashes and local links; no EQL execution. |
| Offline run verifier | `verify_run_evidence.py <run> --offline` | Consistency of committed ledger/artifact assertions; reports `ACCEPTED-LEDGER-ONLY` when accepted. |
| ES-backed run verifier | Same verifier with the retained Elasticsearch environment | Re-fetches source documents and compares event identity/time/host/join fields; recorded RUN-04 report lists 49 references across 49 documents. |
| Operational detections | Per-run alert manifest and query evaluation | Rule-specific observed matches under that run's configuration; does not establish production precision or recall. |
| Reboot experiment | Separate before/after state and process evidence | RUN-04 AV-off survival; independent of the main run window and UAC assertion. |

## Reproduce the available checks

From the repository root:

```bash
python -m unittest discover -s scripts/tests
python tools/validate_repository.py
python scripts/verify/verify_run_evidence.py RUN-20261003-04 --offline
```

For a live re-fetch, supply the environment variables documented by the [verifier/tooling index](../../scripts/README.md) and run:

```bash
python scripts/verify/verify_run_evidence.py RUN-20261003-04
```

Elasticsearch credentials and retained data are prerequisites. Neither command executes the Windows scenario. A clone omits the transferred ZIP bytes by design, so archive verification is limited to the committed receipt/manifest unless the original archive is present. Preparation and execution context are documented in the existing [runbook](../../scripts/runbooks/README.md).

## Latest findings and qualification

| Assertion | RUN-04 support | Remaining boundary |
|---|---|---|
| Medium → High | Before/after mandatory-label measurements plus report's E1 integrity observations | Starting user is a local administrator using a filtered token; before-probe records its measurement caveat. |
| WMI registration | Ordered E19/20/21 with binding-reference checks | Host/time rule candidates alone do not bind specific WMI objects. |
| SYSTEM consumer | Recorded parent/user context under WmiPrvSE | Distinct from proving S2 elevation or identifying every activation from one registration. |
| Transfer | Finalised receipt: `wdmp.zip`, 16,264 bytes, hash and manifest context | First attempt failed; three activations; two connection entities absent; token-holder attribution only. |
| Reboot survival | Objects remain and consumer executes at 08:40:21.543Z | Defender stopped; AV-on pass not executed. |
| Detection volume | 51 stored alerts, 6 S4 alerts; per-alert IDs retained | Unique-cluster total for RUN-04 is not published; do not reuse RUN-03's 14. |
| Cleanup | Archive deletion and run-bound cleanup checks | Subscription intentionally remains installed; no claim that every persistence artifact was removed. |

## Interpreting controls and counts

RUN-03 retains a 5-minute idle control (2026-10-03 10:00–10:05 UTC) with zero matches for the 11 rules. This limited control is not a measured false-positive rate. RUN-03's **14 per-rule clusters / 25 stored alerts** and RUN-04's **51 stored alerts** are different measurements from different windows and activation counts.

The export has **10 building blocks plus S4 as an ordinary alert**. Its one-minute interval overlaps query lookback windows. A larger stored-alert count need not mean more distinct behaviors or improved coverage.

## Threats to validity

- One endpoint, one software stack and development iterations limit generalization. Configurations and starting integrity differ between runs.
- Hashes establish correspondence under the declared raw/canonical conventions; they are not event-native provenance when gathered by a guest probe.
- The reboot check is a separate experiment. Its evidence cannot be counted as an in-window main-run alert.
- Missing connection attribution is retained as a sensor gap, with transfer conclusions drawn from receiver evidence.
- Delivery, remote lateral movement, production noise, broad adversarial variants, ingestion-delay tolerance and AV-on reboot survival remain outside demonstrated coverage.

Future evaluations should record one explicit hypothesis per variant/control, the tested revision/configuration, expected outcome, source events, actual alerts and the reason for any gap. Do not derive recall from technique tags or precision from a short idle window.
