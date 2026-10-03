# reports — Run reports

One report per executed run of the kill chain, following the run-report skeleton
(context/scope → timeline with real event/alert times → per-stage evidence table →
detection volume split → limitations (PARTIAL, gap class, out-of-scope) →
recovery/cleanup → references: ledger, config, commit).

Naming: `reference-run-<run_id>.md` (no date stamps in file names).

| File | Run | Status |
|---|---|---|
| [reference-run-20261003-01.md](reference-run-20261003-01.md) | RUN-20261003-01 | ACCEPTED (query-level detection; rules not yet live) |
| [reference-run-20261003-02.md](reference-run-20261003-02.md) | RUN-20261003-02 | ACCEPTED — live-alert run (rebuild: entity-based E3 ownership) |
| [reference-run-20261003-03.md](reference-run-20261003-03.md) | RUN-20261003-03 | ACCEPTED — final export run: 14 unique clusters / 25 stored alerts |

Reports are written after the acceptance verifier passes; a report never claims more
than the ledger + verifier establish. Labels: design docs are intent; reports are
recorded results.