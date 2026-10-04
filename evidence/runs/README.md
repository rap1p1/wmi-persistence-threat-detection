# evidence — Run records

## Runs

Each run is a directory containing its ledger and artifacts.

| Path | Contents |
|---|---|
| `runs/RUN-schema.json` | ledger schema (stages S1–S7 / input + output artifacts / artifact_index with sha256). Schema is stable across runs; never re-shaped for a run. |
| `runs/RUN-20261003-01/` | first verified run: ledger + artifacts + sink receipt (verifier ACCEPTED, report `reports/reference-run-20261003-01.md`) |
| `runs/RUN-20261003-02/` | live-alert run: ledger + artifacts + sink receipt (rebuilt with entity-based E3 ownership; verifier ACCEPTED, report `reports/reference-run-20261003-02.md`) |
| `runs/RUN-20261003-03/` | final export run: ledger + artifacts + sink receipt (verifier ACCEPTED; 14 unique clusters / 25 stored alerts; report `reports/reference-run-20261003-03.md`) |
| `runs/RUN-20261003-04/` | **Medium-integrity start**: ledger + elevation-before/after + finalised receipt + reboot-survival (AV-off) + alert manifest (report `reports/reference-run-20261003-04.md`) |
| `sanitized-screenshots/` | **historical** April-2026 screenshots with hashes. These are provenance for the earlier analysis, not evidence for any run; keep them out of any acceptance claim. |

## Ledger conventions

- Real `es_id` + `@timestamp` per event row (fetched with
  `scripts/verify/fetch_evidence_ids.py`); "timing approximate (<source>)" is the
  only allowed alternative, and only in `detail`.
- `status` is one of the schema enum; `NOT RUN` must carry an explicit note.
- Artifact hashes: text artifacts indexed with the canonical hash (CRLF→LF
  normalised); binary artifacts (`.zip` etc.) indexed with the raw-byte hash —
  the verifier decides by file suffix. The S3 **module-integrity join** compares the
  RECORDED `svhw.ps1` hash (captured by guest probe; the EID11 event on this stack
  does not populate Hashes — provenance carried in `file_hash_provenance`) against
  the raw sha256 of the staged consumer (`payload/consumer.ps1`, prepared by
  `scripts/prepare_run.ps1`, indexed as ART-01-02).
- The received archive is **not committed** (`*.zip` is gitignored): the sink receipt
  (ART-07-01, name/size/sha256) is the server-side transfer evidence.
- Run-scoped payloads live at `<run_id>/payload/` (prepared by
  `scripts/prepare_run.ps1`) and are indexed like any other artifact.
- Artifacts are written by the sink (`scripts/sink_server.py`) or captured by the
  operator; the run id is verified *inside* each artifact, not just the folder name.
- No credentials anywhere; `secrets_policy` is part of the schema.

## Registering a new run

1. `mkdir evidence/runs/<run_id>/`
2. Execute the chain per `scripts/runbooks/README.md` (sink running, ES creds in env).
3. Fill the ledger rows from `fetch_evidence_ids.py` output; index produced artifacts.
4. `python scripts/verify/verify_run_evidence.py <run_id>` → ACCEPTED.
5. Write `reports/<report>.md` per the §5 skeleton (see `reports/README.md`).