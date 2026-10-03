# evidence — Run records

## Runs

Each run is a directory containing its ledger and artifacts.

| Path | Contents |
|---|---|
| `runs/RUN-schema.json` | ledger schema (stages S1–S7 / input + output artifacts / artifact_index with sha256). Schema is stable across runs; never re-shaped for a run. |
| `runs/RUN-<date>-<seq>/` | one directory per run: `RUN-<id>.json` ledger + artifacts + sink receipt |
| `sanitized-screenshots/` | **historical** April-2026 screenshots with hashes. These are provenance for the earlier analysis, not evidence for any run; keep them out of any acceptance claim. |

## Ledger conventions

- Real `es_id` + `@timestamp` per event row (fetched with
  `scripts/verify/fetch_evidence_ids.py`); "timing approximate (<source>)" is the
  only allowed alternative, and only in `detail`.
- `status` is one of the schema enum; `NOT RUN` must carry an explicit note.
- Artifact hashes: text artifacts indexed with the canonical hash (CRLF→LF
  normalised); binary artifacts (`.zip` etc.) indexed with the raw-byte hash —
  the verifier decides by file suffix.
- Artifacts are written by the sink (`scripts/sink_server.py`) or captured by the
  operator; the run id is verified *inside* each artifact, not just the folder name.
- No credentials anywhere; `secrets_policy` is part of the schema.

## Registering a new run

1. `mkdir evidence/runs/<run_id>/`
2. Execute the chain per `scripts/runbooks/README.md` (sink running, ES creds in env).
3. Fill the ledger rows from `fetch_evidence_ids.py` output; index produced artifacts.
4. `python scripts/verify/verify_run_evidence.py <run_id>` → ACCEPTED.
5. Write `reports/<report>.md` per the §5 skeleton (see `reports/README.md`).