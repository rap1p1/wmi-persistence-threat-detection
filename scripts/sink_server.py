#!/usr/bin/env python3
"""Internal HTTP sink for the WMI lab (transfer-integrity ground truth).

Runs on the lab host, default port 9180, BOUND TO AN EXPLICIT INTERFACE (default the
VMware host-only/NAT lab adapter 192.168.106.1 - never 0.0.0.0). Receives artifacts
via HTTP PUT, writes them into evidence/runs/<run_id>/ and produces the ART-07-01
sink receipt with the observed file name / size / sha256 plus the canonical manifest
hash. The receipt is the transfer-success evidence in the chain.

ATTRIBUTION MODEL (documented limit):
  - The sink authenticates clients with a SHARED LAB TOKEN (X-LAB-Token header,
    SINK_TOKEN env). This is a lab credential, NOT strong authentication: possession
    of the token lets any client on the lab network write artifacts/receipts. The
    claim is therefore "the sink received these bytes from a token-holder on the lab
    network", never "cryptographically attributed to the victim".
  - Without SINK_TOKEN the sink refuses all uploads (fail-closed); the token is
    expected to match the value embedded in the staged consumer (prepare_run.ps1).
  - Receipts are FINALISED: after the first POST /receipt/<run_id>/finalise, any later
    PUT for that run is rejected (409) - a run's transfer evidence cannot be
    overwritten or appended to afterwards.

Endpoints:
  PUT  /artifacts/<run_id>/<artifact_id>/<filename>   (raw body; headers
                                                       X-WMI-Host, X-LAB-Token)
  POST /status/<run_id>                               (JSON status, appended)
  GET  /receipt/<run_id>                              (current receipt)
  POST /receipt/<run_id>/finalise                     (lock the run's receipt)
  GET  /health

Binary artifacts (e.g. .zip) are hashed on raw bytes; text artifacts are hashed
canonically (CRLF->LF). Upload size is bounded (default 64 MB); run ids and artifact
ids are validated; filenames are basenames only.

Usage:
  python scripts/sink_server.py --bind 192.168.106.1 --port 9180
  (SINK_TOKEN=<lab token> python scripts/sink_server.py ...)
"""
import argparse
import hashlib
import hmac
import json
import os
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
    def __init__(self, receipt_dir: Path, max_bytes: int, token: str):
        self.receipt_dir = receipt_dir
        self.max_bytes = max_bytes
        self.token = token

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

    def is_finalised(self, run_id):
        return (self.receipt_dir / run_id / ".finalised").is_file()

    def finalise(self, run_id):
        (self.receipt_dir / run_id / ".finalised").touch()


def _rel(path: Path) -> str:
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

    def _authorised(self):
        """Shared-token check (fail-closed when the sink has no token configured)."""
        expect = self.sink.token
        if not expect:
            return False
        provided = self.headers.get("X-LAB-Token") or ""
        return hmac.compare_digest(provided, expect)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok"})
            return
        m = re.match(r"^/receipt/(RUN-[0-9]{8}-[0-9]{2,})$", self.path)
        if m:
            if not self._authorised():
                self._json(403, {"error": "unauthorised"})
                return
            self._json(200, self.sink.load_receipt(m.group(1)))
            return
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorised():
            self._json(403, {"error": "unauthorised"})
            return
        m = re.match(r"^/status/(RUN-[0-9]{8}-[0-9]{2,})$", self.path)
        if m:
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
            return
        m = re.match(r"^/receipt/(RUN-[0-9]{8}-[0-9]{2,})/finalise$", self.path)
        if m:
            run_id = m.group(1)
            if self.sink.is_finalised(run_id):
                self._json(409, {"error": "already finalised"})
                return
            self.sink.finalise(run_id)
            self._json(200, {"status": "finalised", "run_id": run_id})
            return
        self._json(404, {"error": "expected /status/<run_id> or /receipt/<run_id>/finalise"})

    def do_PUT(self):
        if not self._authorised():
            self._json(403, {"error": "unauthorised"})
            return
        m = re.match(r"^/artifacts/(RUN-[0-9]{8}-[0-9]{2,})/(ART-[0-9]{2}-[0-9]{2})/([^/]+)$",
                     self.path)
        if not m:
            self._json(400, {"error": "expected /artifacts/<run_id>/<artifact_id>/<filename>"})
            return
        run_id, artifact_id, filename = m.groups()
        if Path(filename).name != filename:  # basename enforcement
            self._json(400, {"error": "filename must be a basename"})
            return
        if self.sink.is_finalised(run_id):
            self._json(409, {"error": "run is finalised; uploads rejected"})
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
        payload["sink_interface"] = self.server.server_address[0]
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


def serve(bind, port, receipt_dir, max_bytes, token):
    Handler.sink = Sink(receipt_dir, max_bytes, token)
    server = ThreadingHTTPServer((bind, port), Handler)
    print(f"sink listening on {bind}:{port} (receipt dir: {receipt_dir}; "
          f"token auth: {'on' if token else 'NONE - REFUSING UPLOADS'})")
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default=os.environ.get("SINK_BIND", "192.168.106.1"),
                        help="interface to bind (default the lab adapter 192.168.106.1; "
                             "0.0.0.0 is refused)")
    parser.add_argument("--port", type=int, default=9180)
    parser.add_argument("--receipt-dir", type=Path, default=ROOT / "evidence" / "runs")
    parser.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()
    if args.bind == "0.0.0.0" or args.bind == "::":
        raise SystemExit("refusing to bind 0.0.0.0: the sink must be reachable only on "
                         "the lab interface; bind e.g. 192.168.106.1")
    sys.exit(serve(args.bind, args.port, args.receipt_dir, args.max_bytes,
                   os.environ.get("SINK_TOKEN", "")))