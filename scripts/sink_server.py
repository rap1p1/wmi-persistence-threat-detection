#!/usr/bin/env python3
"""Internal HTTP sink for the WMI lab (transfer-integrity ground truth).

Runs on the lab host, default port 9180. Receives artifacts via HTTP PUT, writes
them into evidence/runs/<run_id>/ and produces the ART-07-01 sink receipt with the
observed file name / size / sha256 plus the canonical manifest hash. The receipt is
the only transfer-success evidence in the chain (see docs/correlation-architecture.md).

Endpoints:
  PUT /artifacts/<run_id>/<artifact_id>/<filename>   (raw body; header X-WMI-Host)
  POST /status/<run_id>                              (JSON status message, appended)
  GET  /health

Binary artifacts (e.g. .zip) are hashed on raw bytes; text artifacts are hashed
canonically (CRLF->LF). Upload size is bounded (default 64 MB). No credentials are
involved; run ids and artifact ids are validated; filenames are basenames only.

Usage:  python scripts/sink_server.py [--port 9180] [--max-bytes 67108864]
"""
import argparse
import hashlib
import json
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUN_ID_RE = re.compile(r"^RUN-[0-9]{8}-[0-9]{2,}$")
ART_ID_RE = re.compile(r"^ART-[0-9]{2}-[0-9]{2}$")
BINARY_SUFFIXES = (".zip", ".7z", ".docm", ".exe", ".dll")


def canon_sha256(data: bytes) -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest().upper()


def raw_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


class Sink:
    def __init__(self, receipt_dir: Path, max_bytes: int):
        self.receipt_dir = receipt_dir
        self.max_bytes = max_bytes

    def receipt_path(self, run_id):
        return self.receipt_dir / run_id / f"ART-07-01-{run_id}.json"

    def load_receipt(self, run_id):
        p = self.receipt_path(run_id)
        if p.is_file():
            return json.loads(p.read_text(encoding="utf-8"))
        return {
            "artifact_id": "ART-07-01",
            "run_id": run_id,
            "kind": "transfer-receipt",
            "payload": {"run_id": run_id, "host": None,
                        "manifest_sha256": None, "sink_files": []}}

    def save_receipt(self, receipt):
        p = self.receipt_path(receipt["run_id"])
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
        return p


def _rel(path: Path) -> str:
    """Repo-relative path when possible, else absolute (receipt dir may be external)."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


class Handler(BaseHTTPRequestHandler):
    sink = None  # set by serve()

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        m = re.match(r"^/status/(RUN-[0-9]{8}-[0-9]{2,})$", self.path)
        if not m:
            self._json(404, {"error": "expected /status/<run_id>"})
            return
        run_id = m.group(1)
        length = int(self.headers.get("Content-Length") or 0)
        if length > self.sink.max_bytes:
            self._json(413, {"error": "status body too large"})
            return
        body = self.rfile.read(length)
        status_dir = self.sink.receipt_dir / run_id
        status_dir.mkdir(parents=True, exist_ok=True)
        with open(status_dir / f"status-{run_id}.jsonl", "ab") as fh:
            fh.write(body + b"\n")
        self._json(200, {"status": "recorded"})

    def do_PUT(self):
        m = re.match(r"^/artifacts/(RUN-[0-9]{8}-[0-9]{2,})/(ART-[0-9]{2}-[0-9]{2})/([^/]+)$",
                     self.path)
        if not m:
            self._json(400, {"error": "expected /artifacts/<run_id>/<artifact_id>/<filename>"})
            return
        run_id, artifact_id, filename = m.groups()
        if Path(filename).name != filename:  # basename enforcement
            self._json(400, {"error": "filename must be a basename"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > self.sink.max_bytes:
            self._json(413, {"error": "upload too large"})
            return
        body = self.rfile.read(length)
        host = self.headers.get("X-WMI-Host") or ""
        if not body:
            self._json(400, {"error": "empty body"})
            return

        run_dir = self.sink.receipt_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        target = run_dir / filename
        target.write_bytes(body)

        if artifact_id == "ART-06-01" or filename.endswith((".txt", ".md")):
            digest = canon_sha256(body)
        else:
            digest = raw_sha256(body)

        receipt = self.sink.load_receipt(run_id)
        payload = receipt.setdefault("payload", {})
        payload["run_id"] = run_id
        payload["host"] = host or payload.get("host")
        if artifact_id == "ART-06-01":
            payload["manifest_sha256"] = digest
            payload["sink_files"] = [f for f in payload.get("sink_files", [])
                                     if f.get("name") != filename]
            payload["sink_files"].append({"name": filename, "size": len(body),
                                          "sha256": digest, "kind": "manifest-snapshot"})
        else:
            payload["sink_files"] = [f for f in payload.get("sink_files", [])
                                     if f.get("name") != filename]
            payload["sink_files"].append({"name": filename, "size": len(body),
                                          "sha256": digest})
        receipt_path = self.sink.save_receipt(receipt)
        self._json(200, {"stored": _rel(target),
                         "sha256": digest, "receipt": _rel(receipt_path)})

    def log_message(self, *args):  # keep the console readable
        pass


def serve(port, receipt_dir, max_bytes):
    Handler.sink = Sink(receipt_dir, max_bytes)
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"sink listening on 0.0.0.0:{port}; receipt dir: {receipt_dir}")
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=9180)
    parser.add_argument("--receipt-dir", type=Path, default=ROOT / "evidence" / "runs")
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()
    sys.exit(serve(args.port, args.receipt_dir, args.max_bytes))