# reports — Run reports

One report per executed run of the kill chain, following the run-report skeleton
(context/scope → timeline with real event/alert times → per-stage evidence table →
detection volume split → limitations (PARTIAL, gap class, out-of-scope) →
recovery/cleanup → references: ledger, config, commit).

Naming: `reference-run-<run_id>.md` (no date stamps in file names).

| File | Run | Status |
|---|---|---|
| (no verified run yet) | — | — |

Reports are written after the acceptance verifier passes; a report never claims more
than the ledger + verifier establish. Labels: design docs are intent; reports are
recorded results.