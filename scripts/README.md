# scripts — evidence, verification and tooling

| Path | Purpose |
|---|---|
| `evidence_lib.py` | Pure evidence helpers (canonical/raw hashing, ledger validation, receipt checks) shared by the verifier and the offline tests. Stdlib only. |
| `verify/verify_run_evidence.py` | Acceptance verifier: ledger structure, stage evidence, artifact hashes, transfer receipt, fail-fast unknown runs, `--all` regression. |
| `verify/fetch_evidence_ids.py` | Fetches real `es_id`/`@timestamp` from Elasticsearch for ledger rows (env-only credentials). |
| `sink_server.py` | Internal transfer sink: receives artifacts over HTTP PUT, writes them into a run dir and produces the ART-07-01 receipt (transfer integrity). |
| `prepare_run.ps1` | Stages run-scoped payloads (run id, sink base, host substituted) under `evidence/runs/<run_id>/payload/` and prints the staged consumer sha256 (ART-01-02, module-integrity link). |
| `rules/gen_rules_ndjson.ps1` | Deterministic rule export generator (rule_id = SHA-256 of name, v5 shape) → `detections/exports/wmi-rules.ndjson`. |
| `runbooks/README.md` | Operator runbook: stages, gates, evidence capture, cleanup. |
| `tests/test_offline.py` | Offline unit tests (rule-id uniqueness, ledger schema negative cases, verifier negative cases, receipt negatives). |

CLI entry points:

```sh
python scripts/tests/test_offline.py
python tools/validate_repository.py
python scripts/verify/verify_run_evidence.py --all --offline
python scripts/verify/verify_run_evidence.py RUN-<date>-<seq>
python scripts/sink_server.py --port 9180
powershell -ExecutionPolicy Bypass -File scripts/prepare_run.ps1 -RunId RUN-<date>-<seq> -SinkBase http://<lab-host>:9180 -HostName <guest>
powershell -ExecutionPolicy Bypass -File scripts/rules/gen_rules_ndjson.ps1
```

Secrets (Elastic URL/user/password) come from the environment only and never appear
in code, ledgers, receipts or exports.