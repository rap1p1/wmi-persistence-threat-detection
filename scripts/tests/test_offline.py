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
            "s4": "s4-curl-upload-intent-connection",
            "c5": "c5-archive-created-then-deleted",
        }
        for r in self.rules:
            name = r["name"].split("]")[0].lstrip("[").lower()
            self.assertIn(name, short, r["name"])
            loaded.add(short[name] + ".eql")
        self.assertEqual(shipped, loaded)

    def test_building_block_mode_enabled(self):
        for r in self.rules:
            self.assertEqual(r.get("building_block_type"), "default", r["name"])
            self.assertIn("Building block", r.get("setup", ""), r["name"])

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
            "secrets_policy": "no-secrets-allowed",
            "stages": [
                {"stage": f"S{i}", "host": "VICTIM", "account": "VICTIM\\victim",
                 "status": "PASS", "input_artifacts": [], "output_artifacts": [],
                 "evidence_refs": [{"kind": "event", "event": "1",
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
            self.assertEqual(vr.es_verify(ledger, failures), 0)
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
                "artifact_index": [],
                "stages": [
                    {"stage": "S2", "host": "wmi", "account": "u", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "event": "1", "ts": "t1", "detail": "fodhelper",
                         "process_name": "fodhelper.exe", "entity_id": "F", "parent_entity_id": "C"},
                        {"kind": "event", "event": "1", "ts": "t2", "detail": "wscript",
                         "process_name": "wscript.exe", "entity_id": "W", "parent_entity_id": "F"},
                        {"kind": "event", "event": "1", "ts": "t3", "detail": "ps",
                         "process_name": "powershell.exe", "entity_id": PS, "parent_entity_id": "W"}]},
                    {"stage": "S3", "host": "wmi", "account": "u", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "event": "19", "ts": "t4", "detail": "f",
                         "wmi_name": "NF", "wmi_operation": "Created"},
                        {"kind": "event", "event": "20", "ts": "t5", "detail": "c",
                         "wmi_name": "SDC", "wmi_operation": "Created"},
                        {"kind": "event", "event": "21", "ts": "t6", "detail": "b",
                         "wmi_consumer": "CommandLineEventConsumer.Name=\"SDC\"",
                         "wmi_filter": "__EventFilter.Name=\"NF\"", "wmi_operation": "Created"}]},
                    {"stage": "S4", "host": "wmi", "account": "SYSTEM", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "event": "1", "ts": "t7", "detail": "consumer",
                         "process_name": "powershell.exe", "entity_id": PS,
                         "parent_entity_id": "WMIPRVSE"}]},
                    {"stage": "S5", "host": "wmi", "account": "SYSTEM", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "event": "1", "ts": "t8", "detail": "arp",
                         "process_name": "arp.exe", "entity_id": "ARP", "parent_entity_id": PS}]},
                    {"stage": "S6", "host": "wmi", "account": "SYSTEM", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "event": "11", "ts": "t9", "detail": "zip",
                         "file_name": "wdmp.zip", "file_path": r"C:\Windows\Temp\wdmp.zip",
                         "entity_id": PS},
                        {"kind": "event", "event": "1", "ts": "t10", "detail": "curl",
                         "process_name": "curl.exe", "entity_id": "CUR", "parent_entity_id": PS},
                        {"kind": "event", "event": "3", "ts": "t11", "detail": "c3",
                         "process_name": "curl.exe", "entity_id": "CUR", "dst_ip": "10.0.0.5"},
                        {"kind": "event", "event": "3", "ts": "t11b", "detail": "ps-status",
                         "process_name": "powershell.exe", "entity_id": PS, "dst_ip": "10.0.0.5"},
                        {"kind": "receipt", "artifact": "ART-07-01-*.json", "detail": "r"}]},
                    {"stage": "S7", "host": "wmi", "account": "SYSTEM", "status": "PASS",
                     "input_artifacts": [], "output_artifacts": [], "evidence_refs": [
                        {"kind": "event", "event": "23", "ts": "t12", "detail": "del",
                         "file_name": "wdmp.zip", "file_path": r"C:\Windows\Temp\wdmp.zip",
                         "entity_id": "CMD"}]},
                ]}

    def test_join_checks_pass(self):
        import verify.verify_run_evidence as vr

        failures = []
        vr.join_checks(self._ledger(), failures)
        self.assertEqual(failures, [])

    def test_join_mismatch_fails(self):
        import verify.verify_run_evidence as vr

        ledger = self._ledger()
        s2 = [s for s in ledger["stages"] if s["stage"] == "S2"][0]
        for r in s2["evidence_refs"]:
            if r["process_name"] == "wscript.exe":
                r["parent_entity_id"] = "WRONG"
        failures = []
        vr.join_checks(ledger, failures)
        self.assertTrue(any("S2 fodhelper->wscript" in f for f in failures), failures)

    def test_archive_path_mismatch_fails(self):
        import verify.verify_run_evidence as vr

        ledger = self._ledger()
        s6 = [s for s in ledger["stages"] if s["stage"] == "S6"][0]
        s7 = [s for s in ledger["stages"] if s["stage"] == "S7"][0]
        s7["evidence_refs"][0]["file_path"] = r"C:\Windows\Temp\other.zip"
        failures = []
        vr.join_checks(ledger, failures)
        self.assertTrue(any("C5 archive-path equality" in f for f in failures), failures)

    def test_binding_mismatch_fails(self):
        import verify.verify_run_evidence as vr

        ledger = self._ledger()
        s3 = [s for s in ledger["stages"] if s["stage"] == "S3"][0]
        e21 = next(r for r in s3["evidence_refs"] if r["event"] == "21")
        e21["wmi_consumer"] = 'CommandLineEventConsumer.Name="OTHER"'
        failures = []
        vr.join_checks(ledger, failures)
        self.assertTrue(any("binding refs mismatch" in f for f in failures), failures)


if __name__ == "__main__":
    unittest.main(verbosity=2)