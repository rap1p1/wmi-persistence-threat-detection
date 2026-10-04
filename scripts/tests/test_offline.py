#!/usr/bin/env python3
"""Offline tests for WMI-LAB-1 evidence/rule components (stdlib unittest only).

Covers the required minimum (playbook 4.1 / 4.2):
  - rule generator output: no duplicate/invalid ids, deterministic from names,
    required_fields cover query fields, query files <-> export one-to-one;
  - ledger schema: valid ledger passes, NOT RUN without note fails, unknown keys and
    statuses fail, missing stage rows fail, artifact hash mismatches fail;
  - verifier logic: placeholder timestamps are rejected, unknown run ids fail fast,
    transfer-receipt negative cases (empty sink_files, hash mismatch) fail.

Run from repo root:  python scripts/tests/test_offline.py
"""
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import evidence_lib as el  # noqa: E402

UUIDV5_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$")


def _query_fields(query):
    plain = re.sub(r"/\*.*?\*/", "", query, flags=re.S)
    return set(re.findall(r"\b(?:winlog|host|user|process|file|destination|event)\.[A-Za-z0-9_.]+",
                          plain))


class RuleExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.export = REPO / "detections" / "exports" / "wmi-rules.ndjson"
        cls.rules = el.parse_ndjson(cls.export)
        cls.query_dir = REPO / "detections" / "queries"

    def test_eleven_rules_and_unique_ids(self):
        self.assertEqual(len(self.rules), 11)
        ids = [r["rule_id"] for r in self.rules]
        self.assertEqual(len(set(ids)), len(ids), "duplicate rule ids")
        self.assertTrue(all(UUIDV5_RE.match(i) for i in ids), "rule id shape")

    def test_deterministic_ids(self):
        for r in self.rules:
            h = __import__("hashlib").sha256(
                ("WMI-LAB:" + r["name"]).encode()).hexdigest()[:32]
            g = list(h)
            g[12], g[16] = "5", "8"
            expected = ("".join(g[0:8]) + "-" + "".join(g[8:12]) + "-" + "".join(g[12:16])
                        + "-" + "".join(g[16:20]) + "-" + "".join(g[20:32]))
            self.assertEqual(r["rule_id"], expected, r["name"])

    def test_required_fields_cover_query(self):
        for r in self.rules:
            declared = {f["name"] for f in r["required_fields"]}
            missing = _query_fields(r["query"]) - declared
            self.assertFalse(missing, f"{r['name']}: undocumented {sorted(missing)}")

    def test_setup_has_detection_basis_and_references(self):
        for r in self.rules:
            self.assertIn("Detection basis:", r["setup"], r["name"])
            self.assertIn("docs/telemetry-contract.md", r["setup"], r["name"])
            self.assertIn("docs/correlation-architecture.md", r["setup"], r["name"])

    def test_query_files_match_export(self):
        shipped = {Path(p).name for p in self.query_dir.glob("*.eql")}
        loaded = set()
        short = {
            "r1": "r1-ms-settings-open-command-registry-hijack",
            "c1": "c1-fodhelper-child-interpreter",
            "s1": "s1-script-host-fodhelper-cmd-parent",
            "s2": "s2-powershell-hidden-bypass-patterns",
            "c2": "c2-wmi-subscription-registration-sequence",
            "r2": "r2-wmi-subscription-registration-activation",
            "s3": "s3-system-shell-wmi-host-parent",
            "c3": "c3-wmi-hosted-interpreter-discovery",
            "c4": "c4-single-process-staging-archive",
            "s4": "s4-script-spawned-curl-upload-args",
            "c5": "c5-archive-created-then-deleted",
        }
        for r in self.rules:
            name = r["name"].split("]")[0].lstrip("[").lower()
            self.assertIn(name, short, r["name"])
            loaded.add(short[name] + ".eql")
        self.assertEqual(shipped, loaded)

    def test_building_block_mode_enabled(self):
        # 10 of 11 rules are building blocks (hidden from default Alerts view);
        # S4 is the analyst-facing upload-intent signal and deliberately carries NO
        # building_block_type so its alerts are visible under default Kibana filters.
        blocks = [r for r in self.rules if r.get("building_block_type") == "default"]
        non_blocks = [r for r in self.rules if not r.get("building_block_type")]
        self.assertEqual(len(blocks), 10)
        self.assertEqual([r["name"] for r in non_blocks],
                         ["[S4] Script-Spawned Curl with Upload Arguments"])
        for r in blocks:
            self.assertIn("Building block", r.get("setup", ""), r["name"])
        for r in non_blocks:
            self.assertIn("NOT a building block", r.get("setup", ""), r["name"])

    def test_threat_payloads_structural_shape(self):
        # regression: PowerShell array-subexpression flattening used to corrupt the
        # MITRE threat JSON (nested subtechniques collapsing to char slices, threat
        # array unrolling to a bare object). The export must keep: threat = [ {...} ],
        # technique = [ {...} ], subtechnique = [ {...} ].
        for r in self.rules:
            t = r.get("threat")
            self.assertIsInstance(t, list, r["name"])
            self.assertTrue(t and isinstance(t[0], dict), r["name"])
            entry = t[0]
            self.assertEqual(entry.get("framework"), "MITRE ATT&CK", r["name"])
            self.assertTrue(str(entry.get("tactic", {}).get("id", "")).startswith("TA"),
                            r["name"])
            self.assertIsInstance(entry.get("technique"), list, r["name"])
            for tech in entry["technique"]:
                self.assertIsInstance(tech, dict, r["name"])
                self.assertTrue(str(tech.get("id", "")).startswith("T"), r["name"])
                for sub in tech.get("subtechnique", []) or []:
                    self.assertIsInstance(sub, dict, r["name"])
                    self.assertEqual(sub["id"].count("."), 1, r["name"])
                    self.assertGreater(len(sub.get("name", "")), 3, r["name"])

    def test_no_actions_no_environment_metadata(self):
        for r in self.rules:
            self.assertEqual(r.get("actions"), [], r["name"])
            self.assertNotIn("meta", r, r["name"])


class LedgerSchemaTests(unittest.TestCase):
    def _valid_ledger(self):
        return {
            "run_id": "RUN-20261013-01",
            "scenario_id": "WMI-LAB-1",
            "created_utc": "2026-10-13T01:00:00Z",
            "run_window_utc": {"start": "2026-10-13T01:00:00Z", "end": "2026-10-13T01:10:00Z"},
            "run_started_utc": "2026-10-13T01:00:05Z",
            "secrets_policy": "no-secrets-allowed",
            "stages": [
                {"stage": f"S{i}", "host": "VICTIM", "account": "VICTIM\\victim",
                 "status": "PASS", "input_artifacts": [], "output_artifacts": [],
                 "evidence_refs": [{"kind": "event", "event": "1", "es_id": f"id{i}",
                                    "ts": "2026-10-13T01:00:05Z", "detail": "x"}]}
                for i in range(1, 8)
            ],
            "artifact_index": [],
        }

    def test_valid_ledger_passes(self):
        self.assertEqual(el.ledger_validate(self._valid_ledger()), [])

    def test_not_run_requires_note(self):
        ledger = self._valid_ledger()
        ledger["stages"][2]["status"] = "NOT RUN"
        errors = el.ledger_validate(ledger)
        self.assertTrue(any("NOT RUN requires an explicit note" in e for e in errors))

    def test_invalid_status_rejected(self):
        ledger = self._valid_ledger()
        ledger["stages"][0]["status"] = "MAYBE"
        self.assertTrue(any("invalid status" in e for e in el.ledger_validate(ledger)))

    def test_unknown_key_rejected(self):
        ledger = self._valid_ledger()
        ledger["stages"][0]["extra"] = True
        self.assertTrue(any("unexpected keys" in e for e in el.ledger_validate(ledger)))
        ledger2 = self._valid_ledger()
        ledger2["whoami"] = "x"
        self.assertTrue(any("unexpected top-level keys" in e for e in el.ledger_validate(ledger2)))

    def test_missing_stage_row_rejected(self):
        ledger = self._valid_ledger()
        ledger["stages"] = ledger["stages"][:5]
        self.assertTrue(any("missing stage row" in e for e in el.ledger_validate(ledger)))

    def test_artifact_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            f = d / "a.txt"
            f.write_bytes(b"hello\r\n")
            ledger = self._valid_ledger()
            ledger["artifact_index"] = [
                {"artifact_id": "ART-06-01", "path": "a.txt",
                 "sha256": "A" * 64, "producer_stage": "S5", "consumer_stage": "S6"}]
            errors = el.artifact_violations(ledger, d)
            self.assertTrue(any("hash mismatch" in e for e in errors))
            ledger["artifact_index"][0]["sha256"] = el.canon_sha256(b"hello\n")
            self.assertEqual(el.artifact_violations(ledger, d), [])

    def test_canonical_vs_raw_hash(self):
        data = b"line1\r\nline2\n"
        self.assertEqual(el.canon_sha256(data), el.canon_sha256(b"line1\nline2\n"))
        self.assertNotEqual(el.raw_sha256(data), el.canon_sha256(data))
        self.assertEqual(el.raw_sha256(data),
                         __import__("hashlib").sha256(data).hexdigest().upper())


class TransferReceiptTests(unittest.TestCase):
    def _receipt(self, files=None, manifest=None):
        files = files if files is not None else [
            {"name": "wdmp.zip", "size": 10, "sha256": "B" * 64}]
        return {
            "run_id": "RUN-20261013-01",
            "kind": "transfer-receipt",
            "payload": {
                "run_id": "RUN-20261013-01", "host": "VICTIM",
                "manifest_text": manifest or "Files: 2\n  a.txt [3 bytes]\n",
                "manifest_sha256": el.canon_sha256(
                    (manifest or "Files: 2\n  a.txt [3 bytes]\n").encode()),
                "sink_files": files,
            },
        }

    def test_valid_receipt_passes(self):
        self.assertEqual(el.receipt_validate(self._receipt()), [])

    def test_empty_sink_files_fail(self):
        errors = el.receipt_validate(self._receipt(files=[]))
        self.assertTrue(any("sink_files empty" in e for e in errors))

    def test_missing_file_fields_fail(self):
        errors = el.receipt_validate(self._receipt(files=[{"name": "wdmp.zip"}]))
        self.assertTrue(any("missing" in e for e in errors))

    def test_manifest_hash_consistency(self):
        r = self._receipt()
        self.assertEqual(el.manifest_hash_of(r), r["payload"]["manifest_sha256"])
        r["payload"]["manifest_text"] = "tampered"
        self.assertNotEqual(el.manifest_hash_of(r), r["payload"]["manifest_sha256"])


class VerifierLogicTests(unittest.TestCase):
    def test_placeholder_timestamps_rejected(self):
        import verify.verify_run_evidence as vr

        ledger = {
            "stages": [
                {"stage": "S1", "evidence_refs": [
                    {"kind": "event", "event": "1", "ts": "2026-10-13T01:00:5xZ",
                     "detail": "placeholder"}]},
                {"stage": "S2", "evidence_refs": [
                    {"kind": "event", "event": "1", "ts": "", "detail": "no ts"}]},
            ]}
        bad = vr._check_placeholders(ledger)
        self.assertEqual(len(bad), 2)

    def test_unknown_run_fails_fast(self):
        import verify.verify_run_evidence as vr

        with self.assertRaises(SystemExit):
            vr._load_ledger("RUN-99999999-99")

    def test_validate_run_negative(self):
        import verify.verify_run_evidence as vr
        from unittest import mock

        ledger = {
            "run_id": "RUN-20261013-01", "scenario_id": "WMI-LAB-1",
            "created_utc": "2026-10-13T01:00:00Z", "secrets_policy": "no-secrets-allowed",
            "stages": [
                {"stage": f"S{i}", "host": "VICTIM", "account": "VICTIM\\victim",
                 "status": "PASS" if i != 6 else "NOT RUN",
                 "input_artifacts": [], "output_artifacts": [],
                 "evidence_refs": [{"kind": "event", "event": "1", "ts": "2026-10-13T01:00:05Z",
                                    "detail": "x"}]}
                for i in range(1, 7)
            ],  # S7 missing on purpose
            "artifact_index": [],
        }
        failures = []
        with mock.patch.object(vr, "ROOT", REPO):
            vr.validate_run(ledger, REPO / "evidence" / "runs" / "RUN-20261013-01", failures)
        self.assertTrue(any("missing mandatory stage rows" in f for f in failures))
        self.assertTrue(any("NOT RUN" in f for f in failures))


class TimestampToleranceTests(unittest.TestCase):
    def test_within_tolerance(self):
        self.assertTrue(el.ts_within("2026-10-13T01:00:05.100Z",
                                     "2026-10-13T01:00:05.200Z", 1.0))
        self.assertTrue(el.ts_within("2026-10-13T01:00:05Z",
                                     "2026-10-13T01:00:07Z", 5.0))

    def test_outside_tolerance(self):
        self.assertFalse(el.ts_within("2026-10-13T01:00:05Z",
                                      "2026-10-13T01:00:20Z", 5.0))

    def test_unparseable_returns_none(self):
        self.assertIsNone(el.ts_within("12:34:5xZ", "2026-10-13T01:00:05Z"))
        self.assertIsNone(el.ts_within("2026-10-13T01:00:05Z", ""))

    def test_es_verify_noop_without_creds(self):
        import os
        import verify.verify_run_evidence as vr
        from unittest import mock

        ledger = {"stages": [{"stage": "S1", "evidence_refs": [
            {"kind": "event", "es_id": "x", "ts": "2026-10-13T01:00:05Z"}]}]}
        failures = []
        with mock.patch.dict(os.environ, {"ES_URL": "", "ES_PASS": ""}):
            self.assertEqual(vr.es_verify(ledger, failures), (0, 0))
        self.assertEqual(failures, [])


def test_s3_module_integrity(self):
        import verify.verify_run_evidence as vr

        def full_ledger():
            stages = []
            for i in range(1, 8):
                stages.append({"stage": f"S{i}", "host": "VICTIM",
                               "account": "VICTIM\\victim", "status": "PASS",
                               "input_artifacts": [], "output_artifacts": [],
                               "evidence_refs": [{"kind": "event", "event": "1",
                                                  "ts": "2026-10-13T01:00:05Z",
                                                  "detail": "x"}]})
            return {"run_id": "RUN-20261013-01", "scenario_id": "WMI-LAB-1",
                    "created_utc": "2026-10-13T01:00:00Z",
                    "secrets_policy": "no-secrets-allowed",
                    "stages": stages, "artifact_index": []}

        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "payload").mkdir()
            (d / "payload" / "consumer.ps1").write_bytes(b"$x = 1\r\n")
            raw = el.raw_sha256((d / "payload" / "consumer.ps1").read_bytes())

            # positive: EID 11 file_hash matches the staged consumer raw hash
            ledger = full_ledger()
            ledger["stages"][2]["evidence_refs"] = [
                {"kind": "event", "event": "11", "ts": "2026-10-13T01:00:05Z",
                 "detail": "svhw.ps1", "file_hash": raw}]
            ledger["artifact_index"] = [
                {"artifact_id": "ART-01-02", "path": "payload/consumer.ps1",
                 "sha256": el.canon_sha256(b"$x = 1\n"),
                 "producer_stage": "S3", "consumer_stage": "S3"}]
            failures = []
            vr.validate_run(ledger, d, failures)
            self.assertFalse([f for f in failures if "module integrity" in f], failures)

            # negative: tampered staged consumer does NOT match the recorded hash
            (d / "payload" / "consumer.ps1").write_bytes(b"$x = 2\r\n")
            failures = []
            vr.validate_run(ledger, d, failures)
            self.assertTrue(any("module integrity mismatch" in f for f in failures), failures)


class JoinCheckTests(unittest.TestCase):
    """Chain-of-evidence joins (ancestry/ownership/path/binding) in the verifier."""

    def _ledger(self):
        E = "E"
        PS = "PS"
        W = "W"
        return {"run_id": "RUN-20261013-01", "scenario_id": "WMI-LAB-1",
                "created_utc": "2026-10-13T01:00:00Z", "secrets_policy": "no-secrets-allowed",
                "run_window_utc": {"start": "2026-10-13T01:00:00Z", "end": "2026-10-13T01:10:00Z"},
                "artifact_index": [],
                "stages": [
                    {"stage": "S2", "host": "wmi", "account": "u", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "es_id": "j1", "event": "1", "ts": "2026-10-13T01:00:06Z", "detail": "fodhelper",
                         "process_name": "fodhelper.exe", "entity_id": "F", "parent_entity_id": "C"},
                        {"kind": "event", "es_id": "j2", "event": "1", "ts": "2026-10-13T01:00:07Z", "detail": "wscript",
                         "process_name": "wscript.exe", "entity_id": "W", "parent_entity_id": "F"},
                        {"kind": "event", "es_id": "j3", "event": "1", "ts": "2026-10-13T01:00:08Z", "detail": "ps",
                         "process_name": "powershell.exe", "entity_id": PS, "parent_entity_id": "W"}]},
                    {"stage": "S3", "host": "wmi", "account": "u", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "es_id": "j4", "event": "19", "ts": "2026-10-13T01:00:09Z", "detail": "f",
                         "wmi_name": "NF", "wmi_operation": "Created"},
                        {"kind": "event", "es_id": "j5", "event": "20", "ts": "2026-10-13T01:00:10Z", "detail": "c",
                         "wmi_name": "SDC", "wmi_operation": "Created"},
                        {"kind": "event", "es_id": "j6", "event": "21", "ts": "2026-10-13T01:00:11Z", "detail": "b",
                         "wmi_consumer": "CommandLineEventConsumer.Name=\"SDC\"",
                         "wmi_filter": "__EventFilter.Name=\"NF\"", "wmi_operation": "Created"}]},
                    {"stage": "S4", "host": "wmi", "account": "SYSTEM", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "es_id": "j7", "event": "1", "ts": "2026-10-13T01:00:12Z", "detail": "consumer",
                         "process_name": "powershell.exe", "entity_id": PS,
                         "parent_entity_id": "WMIPRVSE", "parent_name": "WmiPrvSE.exe",
                         "user": "NT AUTHORITY\\SYSTEM"}]},
                    {"stage": "S5", "host": "wmi", "account": "SYSTEM", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "es_id": "j8", "event": "1", "ts": "2026-10-13T01:00:13Z", "detail": "arp",
                         "process_name": "ARP.EXE", "entity_id": "ARP", "parent_entity_id": PS}]},
                    {"stage": "S6", "host": "wmi", "account": "SYSTEM", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "es_id": "j9", "event": "11", "ts": "2026-10-13T01:00:14Z", "detail": "zip",
                         "file_name": "wdmp.zip", "file_path": r"C:\Windows\Temp\wdmp.zip",
                         "entity_id": PS},
                        {"kind": "event", "es_id": "j10", "event": "1", "ts": "2026-10-13T01:00:15Z", "detail": "curl",
                         "process_name": "curl.exe", "entity_id": "CUR", "parent_entity_id": PS},
                        {"kind": "event", "es_id": "j11", "event": "3", "ts": "2026-10-13T01:00:16Z", "detail": "c3",
                         "process_name": "curl.exe", "entity_id": "CUR",
                         "dst_ip": "192.168.106.1", "dst_port": 9180},
                        {"kind": "event", "es_id": "j12", "event": "3", "ts": "2026-10-13T01:00:17Z", "detail": "ps-status",
                         "process_name": "powershell.exe", "entity_id": PS,
                         "dst_ip": "192.168.106.1", "dst_port": 9180},
                        {"kind": "receipt", "artifact": "ART-07-01-*.json", "detail": "r"}]},
                    {"stage": "S7", "host": "wmi", "account": "SYSTEM", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "es_id": "j13", "event": "23", "ts": "2026-10-13T01:00:18Z", "detail": "del",
                         "file_name": "wdmp.zip", "file_path": r"C:\Windows\Temp\wdmp.zip",
                         "entity_id": "CMD"}]},
                ]}

    def test_join_checks_pass(self):
        import verify.verify_run_evidence as vr

        failures, gaps = [], []
        vr.join_checks(self._ledger(), failures, gaps)
        self.assertEqual(failures, [])

    def test_join_mismatch_fails(self):
        import verify.verify_run_evidence as vr

        ledger = self._ledger()
        s2 = [s for s in ledger["stages"] if s["stage"] == "S2"][0]
        for r in s2["evidence_refs"]:
            if r["process_name"] == "wscript.exe":
                r["parent_entity_id"] = "WRONG"
        failures, gaps = [], []
        vr.join_checks(ledger, failures, gaps)
        self.assertTrue(any("S2 fodhelper->wscript" in f for f in failures), failures)

    def test_binding_mismatch_fails(self):
        import verify.verify_run_evidence as vr

        ledger = self._ledger()
        s3 = [s for s in ledger["stages"] if s["stage"] == "S3"][0]
        e21 = next(r for r in s3["evidence_refs"] if r["event"] == "21")
        e21["wmi_consumer"] = 'CommandLineEventConsumer.Name="OTHER"'
        failures, gaps = [], []
        vr.join_checks(ledger, failures, gaps)
        self.assertTrue(any("do not match the recorded objects" in f for f in failures), failures)

    def test_e3_join_by_entity_without_name(self):
        """A name-less E3 (Sysmon 'unknown process') with a matching entity must pass
        the ownership join (entity is the technical key, not the name)."""
        import verify.verify_run_evidence as vr

        ledger = self._ledger()
        s6 = [s for s in ledger["stages"] if s["stage"] == "S6"][0]
        for r in s6["evidence_refs"]:
            if r.get("event") == "3" and r.get("process_name") == "curl.exe":
                r["process_name"] = None  # simulate Image: <unknown process>
        failures, gaps = [], []
        vr.join_checks(ledger, failures, gaps)
        self.assertEqual(failures, [])
        self.assertEqual(gaps, [])




class NegativeAcceptanceTests(unittest.TestCase):
    """Acceptance-path negatives: each mutation must FAIL the verifier."""

    def _valid_run(self):
        import tempfile
        tmp = tempfile.TemporaryDirectory()
        d = Path(tmp.name)
        (d / "payload").mkdir()
        (d / "payload" / "consumer.ps1").write_bytes(b"$x = 1\r\n")
        raw = el.raw_sha256((d / "payload" / "consumer.ps1").read_bytes())
        W0, W1 = "2026-10-13T01:00:00Z", "2026-10-13T01:10:00Z"
        E = "PS"
        stages = [
            {"stage": "S1", "host": "wmi", "account": "u", "status": "PASS",
             "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                 {"kind": "event", "es_id": "s1", "ts": "2026-10-13T01:00:05Z", "event": "1",
                  "process_name": "cmd.exe", "entity_id": "C"}]},
            {"stage": "S2", "host": "wmi", "account": "u", "status": "PASS",
             "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                 {"kind": "event", "es_id": "s2a", "ts": "2026-10-13T01:00:06Z", "event": "13",
                  "process_name": "reg.exe", "registry_path": "HKU\\x\\ms-settings\\Shell\\Open\\command\\(Default)"},
                 {"kind": "event", "es_id": "s2b", "ts": "2026-10-13T01:00:07Z", "event": "1",
                  "process_name": "fodhelper.exe", "entity_id": "F", "parent_entity_id": "C"},
                 {"kind": "event", "es_id": "s2c", "ts": "2026-10-13T01:00:08Z", "event": "1",
                  "process_name": "wscript.exe", "entity_id": "W", "parent_entity_id": "F"},
                 {"kind": "event", "es_id": "s2d", "ts": "2026-10-13T01:00:09Z", "event": "1",
                  "process_name": "powershell.exe", "entity_id": E, "parent_entity_id": "W"}]},
            {"stage": "S3", "host": "wmi", "account": "u", "status": "PASS",
             "input_artifacts": ["ART-01-02"], "output_artifacts": [], "evidence_refs": [
                 {"kind": "event", "es_id": "s3a", "ts": "2026-10-13T01:00:10Z", "event": "11",
                  "process_name": "powershell.exe", "file_path": "C:\\Windows\\Temp\\svhw.ps1",
                  "file_hash": raw, "file_hash_provenance": "unit test"},
                 {"kind": "event", "es_id": "s3b", "ts": "2026-10-13T01:00:11Z", "event": "19",
                  "wmi_name": "NF", "wmi_operation": "Created"},
                 {"kind": "event", "es_id": "s3c", "ts": "2026-10-13T01:00:12Z", "event": "20",
                  "wmi_name": "SDC", "wmi_operation": "Created"},
                 {"kind": "event", "es_id": "s3d", "ts": "2026-10-13T01:00:13Z", "event": "21",
                  "wmi_consumer": 'CommandLineEventConsumer.Name="SDC"',
                  "wmi_filter": '__EventFilter.Name="NF"'}]},
            {"stage": "S4", "host": "wmi", "account": "SYSTEM", "status": "PASS",
             "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                 {"kind": "event", "es_id": "s4a", "ts": "2026-10-13T01:01:00Z", "event": "1",
                  "process_name": "notepad.exe", "user": "wmi\\Duc"},
                 {"kind": "event", "es_id": "s4b", "ts": "2026-10-13T01:01:01Z", "event": "1",
                  "process_name": "powershell.exe", "user": "NT AUTHORITY\\SYSTEM",
                  "entity_id": E, "parent_entity_id": "WMIPRVSE",
                  "parent_name": "WmiPrvSE.exe"}]},
            {"stage": "S5", "host": "wmi", "account": "SYSTEM", "status": "PASS",
             "input_artifacts": [], "output_artifacts": ["ART-06-01"], "evidence_refs": [
                 {"kind": "event", "es_id": "s5a", "ts": "2026-10-13T01:01:05Z", "event": "1",
                  "process_name": "ARP.EXE", "entity_id": "A", "parent_entity_id": E},
                 {"kind": "event", "es_id": "s5b", "ts": "2026-10-13T01:01:06Z", "event": "11",
                  "process_name": "powershell.exe", "file_path": "C:\\Windows\\Temp\\wdmp\\info.txt"},
                 {"kind": "event", "es_id": "s5c", "ts": "2026-10-13T01:01:07Z", "event": "11",
                  "process_name": "powershell.exe", "file_path": "C:\\Windows\\Temp\\wdmp\\_manifest.txt"}]},
            {"stage": "S6", "host": "wmi", "account": "SYSTEM", "status": "PASS",
             "input_artifacts": ["ART-06-01"], "output_artifacts": ["ART-07-01"],
             "evidence_refs": [
                 {"kind": "event", "es_id": "s6a", "ts": "2026-10-13T01:01:20Z", "event": "11",
                  "process_name": "powershell.exe", "entity_id": E,
                  "file_path": "C:\\Windows\\Temp\\wdmp.zip"},
                 {"kind": "event", "es_id": "s6b", "ts": "2026-10-13T01:01:21Z", "event": "1",
                  "process_name": "curl.exe", "entity_id": "CUR", "parent_entity_id": E},
                 {"kind": "event", "es_id": "s6c", "ts": "2026-10-13T01:01:22Z", "event": "3",
                  "entity_id": "CUR", "dst_ip": "192.168.106.1", "dst_port": 9180},
                 {"kind": "event", "es_id": "s6d", "ts": "2026-10-13T01:01:23Z", "event": "3",
                  "process_name": "powershell.exe", "entity_id": E,
                  "dst_ip": "192.168.106.1", "dst_port": 9180},
                 {"kind": "receipt", "artifact": "ART-07-01-*.json", "detail": "receipt"}]},
            {"stage": "S7", "host": "wmi", "account": "SYSTEM", "status": "PASS",
             "input_artifacts": [], "output_artifacts": ["ART-08-01"], "evidence_refs": [
                 {"kind": "event", "es_id": "s7a", "ts": "2026-10-13T01:01:30Z", "event": "23",
                  "file_path": "C:\\Windows\\Temp\\wdmp.zip"}]},
        ]
        man = d / "_manifest.txt"
        man.write_bytes(b"Files: 1\r\n")
        man_hash = el.canon_sha256(man.read_bytes())
        receipt = {"artifact_id": "ART-07-01", "run_id": "RUN-20261013-01",
                   "kind": "transfer-receipt",
                   "payload": {"run_id": "RUN-20261013-01", "host": "wmi",
                               "manifest_sha256": man_hash,
                               "sink_files": [{"name": "wdmp.zip", "size": 10,
                                               "sha256": "B" * 64}]}}
        (d / "ART-07-01-RUN-20261013-01.json").write_text(json.dumps(receipt), encoding="utf-8")
        clean = {"run_id": "RUN-20261013-01",
                 "checks": [{"check": "wdmp.zip removed", "result": "PASS"}]}
        (d / "ART-08-01-RUN-20261013-01.json").write_text(json.dumps(clean), encoding="utf-8")
        ledger = {"run_id": "RUN-20261013-01", "scenario_id": "WMI-LAB-1",
                  "created_utc": "2026-10-13T01:10:00Z",
                  "run_window_utc": {"start": W0, "end": W1},
                  "run_started_utc": "2026-10-13T01:00:05Z",
                  "secrets_policy": "no-secrets-allowed", "stages": stages,
                  "artifact_index": [
                      {"artifact_id": "ART-01-02", "path": "payload/consumer.ps1",
                       "sha256": el.canon_sha256(b"$x = 1\n"), "producer_stage": "S3",
                       "consumer_stage": "S7"},
                      {"artifact_id": "ART-06-01", "path": "_manifest.txt",
                       "sha256": man_hash, "producer_stage": "S5", "consumer_stage": "S6"},
                      {"artifact_id": "ART-07-01", "path": "ART-07-01-RUN-20261013-01.json",
                       "sha256": el.canon_sha256((d / "ART-07-01-RUN-20261013-01.json").read_bytes()),
                       "producer_stage": "S6", "consumer_stage": ""},
                      {"artifact_id": "ART-08-01", "path": "ART-08-01-RUN-20261013-01.json",
                       "sha256": el.canon_sha256((d / "ART-08-01-RUN-20261013-01.json").read_bytes()),
                       "producer_stage": "S7", "consumer_stage": ""}]}
        return tmp, d, ledger

    def _fail(self, mutate):
        import verify.verify_run_evidence as vr

        tmp, d, ledger = self._valid_run()
        try:
            mutate(ledger, d)
            failures, gaps = [], []
            vr.validate_run(ledger, d, failures, gaps)
            return failures
        finally:
            tmp.cleanup()

    def test_baseline_ledger_passes(self):
        self.assertEqual(self._fail(lambda l, d: None), [])

    def test_duplicate_event_id_fails(self):
        def m(l, d):
            l["stages"][5]["evidence_refs"].append(dict(l["stages"][5]["evidence_refs"][0]))
        self.assertTrue(any("duplicate event refs" in f for f in self._fail(m)))

    def test_placeholder_timestamp_fails(self):
        def m(l, d):
            l["stages"][0]["evidence_refs"][0]["ts"] = "2026-10-13T01:00:5xZ"
        self.assertTrue(any("outside the run window" in f or "not ISO-8601" in f
                            for f in self._fail(m)))

    def test_missing_module_hash_fails(self):
        def m(l, d):
            l["stages"][2]["evidence_refs"][0].pop("file_hash")
        self.assertTrue(any("module hash missing" in f for f in self._fail(m)))

    def test_event_outside_window_fails(self):
        def m(l, d):
            l["stages"][0]["evidence_refs"][0]["ts"] = "2026-10-13T00:00:00Z"
        self.assertTrue(any("outside the run window" in f for f in self._fail(m)))

    def test_receipt_wrong_run_fails(self):
        def m(l, d):
            p = d / "ART-07-01-RUN-20261013-01.json"
            r = json.loads(p.read_text())
            r["payload"]["run_id"] = "RUN-20261013-99"
            p.write_text(json.dumps(r))
            l["artifact_index"][2]["sha256"] = el.canon_sha256(p.read_bytes())
        self.assertTrue(any("receipt run_id" in f for f in self._fail(m)))

    def test_receipt_bad_size_fails(self):
        def m(l, d):
            p = d / "ART-07-01-RUN-20261013-01.json"
            r = json.loads(p.read_text())
            r["payload"]["sink_files"][0]["size"] = "10"
            p.write_text(json.dumps(r))
            l["artifact_index"][2]["sha256"] = el.canon_sha256(p.read_bytes())
        self.assertTrue(any("size must be a positive integer" in f for f in self._fail(m)))

    def test_receipt_manifest_mismatch_fails(self):
        def m(l, d):
            p = d / "ART-07-01-RUN-20261013-01.json"
            r = json.loads(p.read_text())
            r["payload"]["manifest_sha256"] = "C" * 64
            p.write_text(json.dumps(r))
            l["artifact_index"][2]["sha256"] = el.canon_sha256(p.read_bytes())
        self.assertTrue(any("manifest_sha256" in f for f in self._fail(m)))

    def test_cleanup_check_fail_fails(self):
        def m(l, d):
            p = d / "ART-08-01-RUN-20261013-01.json"
            c = {"run_id": "RUN-20261013-01",
                 "checks": [{"check": "wdmp.zip removed", "result": "FAIL"}]}
            p.write_text(json.dumps(c))
            l["artifact_index"][3]["sha256"] = el.canon_sha256(p.read_bytes())
        self.assertTrue(any("cleanup check not PASS" in f for f in self._fail(m)))

    def test_entity_mismatch_fails(self):
        def m(l, d):
            s6 = l["stages"][5]["evidence_refs"]
            curl1 = next(r for r in s6 if r.get("event") == "1"
                         and r.get("process_name") == "curl.exe")
            e3 = next(r for r in s6 if r.get("event") == "3"
                      and r.get("entity_id") == curl1["entity_id"])
            e3["entity_id"] = "FOREIGN"   # E3 now contradicts the curl E1 entity
        fails = self._fail(m)
        self.assertTrue(any("S6" in f for f in fails), fails)

    def test_archive_path_mismatch_fails(self):
        def m(l, d):
            for r in l["stages"][6]["evidence_refs"]:
                if r.get("event") == "23":
                    r["file_path"] = "C:\\Windows\\Temp\\other.zip"
        fails = self._fail(m)
        self.assertTrue(any("archive-path equality" in f for f in fails), fails)

    def test_path_traversal_fails(self):
        def m(l, d):
            l["artifact_index"][0]["path"] = "../../etc/passwd"
        self.assertTrue(any("traversal" in f for f in self._fail(m)))

    def test_s4_non_system_fails(self):
        def m(l, d):
            l["stages"][3]["evidence_refs"][1]["user"] = "wmi\\Duc"
        self.assertTrue(any("not SYSTEM" in f for f in self._fail(m)))

    def test_c2_partial_substring_no_longer_passes(self):
        def m(l, d):
            l["stages"][2]["evidence_refs"][3]["wmi_filter"] = '__EventFilter.Name="NotepadFilterX"'
        self.assertTrue(any("do not match the recorded objects" in f for f in self._fail(m)))


    def test_elevation_transition_absent_fails(self):
        """Both measurements captured but no Medium->High rise must FAIL."""
        def m(l, d):
            for stage, label in (('before', 'Medium'), ('after', 'Medium')):
                (d / f"elevation-{stage}.json").write_text(
                    json.dumps({"current_session": {"integrity_label": label}}))
        self.assertTrue(any("elevation transition not demonstrated" in f
                            for f in self._fail(m)))

    def test_elevation_measurements_pass(self):
        def m(l, d):
            (d / "elevation-before.json").write_text(
                json.dumps({"current_session": {"integrity_label": "Medium"}}))
            (d / "elevation-after.json").write_text(
                json.dumps({"current_session": {"integrity_label": "High"}}))
        self.assertEqual(self._fail(m), [])

class EqlSourceExportDriftTests(unittest.TestCase):
    """A one-character drift between the .eql source and the exported query fails."""

    def test_normalize_and_compare(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "validator", REPO / "tools" / "validate_repository.py")
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        src = REPO / "detections" / "queries" / "c5-archive-created-then-deleted.eql"
        text = src.read_text(encoding="utf-8")
        rules = el.parse_ndjson(REPO / "detections" / "exports" / "wmi-rules.ndjson")
        c5 = next(r for r in rules if r["name"].startswith("[C5]"))
        self.assertEqual(validator.normalize_eql(text), validator.normalize_eql(c5["query"]))
        drifted = text.replace("maxspan=2m", "maxspan=3m")
        self.assertNotEqual(validator.normalize_eql(drifted),
                            validator.normalize_eql(c5["query"]))



if __name__ == "__main__":
    unittest.main(verbosity=2)