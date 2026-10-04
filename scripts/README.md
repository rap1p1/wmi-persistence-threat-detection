# scripts — evidence, verification and tooling

| Path | Purpose |
|---|---|
| `evidence_lib.py` | Pure evidence helpers (canonical/raw hashing, ledger validation, receipt checks) shared by the verifier and the offline tests. Stdlib only. |
| `verify/verify_run_evidence.py` | Acceptance verifier: ledger structure, stage evidence, artifact hashes, transfer receipt, fail-fast unknown runs, `--all` regression. |
| `verify/fetch_evidence_ids.py` | Fetches real `es_id`/`@timestamp` from Elasticsearch for ledger rows (env-only credentials). |
| `sink_server.py` | Internal transfer sink: BOUND to the lab interface (`--bind 192.168.106.1`; 0.0.0.0 refused), shared-lab-token auth (`SINK_TOKEN`/`X-LAB-Token`), receipts finalisable per run so they cannot be overwritten. |
| `prepare_run.ps1` | Stages run-scoped payloads (run id, sink base, host, sink token) under `evidence/runs/<run_id>/payload/`; refuses sinks outside the lab range (192.168.x.x) and prints the staged consumer sha256 (ART-01-02; module integrity is the GUEST PROBE, not an EID 11 hash). |
| `rules/gen_rules_ndjson.ps1` | Deterministic rule export generator (rule_id = SHA-256 of name, v5 shape) → `detections/exports/wmi-rules.ndjson`. |
| `runbooks/README.md` | Operator runbook: stages, gates, evidence capture, cleanup (includes sink/token steps, reboot-survival and elevation-preflight pointers). |
| `tests/test_offline.py` | Offline unit tests (rule-id uniqueness, query/export drift, ledger schema negatives, verifier negatives incl. receipt/cleanup/elevation-gate/path-traversal). |

CLI entry points:

```sh
python scripts/tests/test_offline.py
python tools/validate_repository.py
python scripts/verify/verify_run_evidence.py --all --offline
python scripts/verify/verify_run_evidence.py RUN-<date>-<seq>
python scripts/sink_server.py --bind 192.168.106.1 --port 9180   # SINK_TOKEN=<token>
powershell -ExecutionPolicy Bypass -File scripts/prepare_run.ps1 -RunId RUN-<date>-<seq> -SinkBase http://192.168.106.1:9180 -HostName <guest> -SinkToken <token>
powershell -ExecutionPolicy Bypass -File scripts/rules/gen_rules_ndjson.ps1
```

Secrets (Elastic URL/user/password) come from the environment only and never appear
in code, ledgers, receipts or exports.