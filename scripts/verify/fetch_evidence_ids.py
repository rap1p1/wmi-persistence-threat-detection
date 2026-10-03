#!/usr/bin/env python3
"""Fetch real event ids/timestamps from Elasticsearch for a run stage.

Prints one JSON object per hit: {_id, @timestamp, event.code, host, key fields}.
The operator copies these into the run ledger `evidence_refs` rows — this is the
only place run evidence enters the ledger; nothing here is inferred or fabricated.

Usage:
  set ES_URL=... & set ES_USER=elastic & set ES_PASS=... & \\
  python scripts/verify/fetch_evidence_ids.py --index sysmon --event-code 19 \\
      --filter 'winlog.event_data.Name:"NotepadFilter"' --window 2026-10-13T01:00:00Z,2026-10-13T01:10:00Z
"""
import argparse
import base64
import json
import os
import ssl
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

INDEXES = {
    "sysmon": ".ds-logs-windows.sysmon_operational-*",
    "security": ".ds-logs-system.security-*",
    "alerts": ".internal.alerts-security.alerts-default-*",
}
FIELDS = ("process.name", "process.parent.name", "process.entity_id",
          "process.parent.entity_id", "user.name", "winlog.event_id",
          "winlog.event_data.Name", "winlog.event_data.Operation",
          "winlog.event_data.Consumer", "winlog.event_data.Filter",
          "winlog.event_data.TargetObject", "winlog.event_data.Details",
          "file.path", "file.name", "file.extension", "file.hash.sha256",
          "destination.ip", "destination.port", "host.name", "event.code")


def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", choices=sorted(INDEXES), required=True)
    parser.add_argument("--event-code", help="expected Sysmon/Security event code (for display)")
    parser.add_argument("--filter", default="", help="KQL filter fragment for the bool query")
    parser.add_argument("--window", required=True, help="start,end (ISO-8601 Z)")
    parser.add_argument("--size", type=int, default=10)
    args = parser.parse_args(argv)

    url = os.environ.get("ES_URL")
    user = os.environ.get("ES_USER", "elastic")
    password = os.environ.get("ES_PASS")
    if not (url and password):
        raise SystemExit("ES_URL and ES_PASS must be set in the environment")

    w0, w1 = (x.strip() for x in args.window.split(","))
    body = {
        "size": args.size,
        "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": [{"range": {"@timestamp": {"gte": w0, "lte": w1}}}]}},
        "_source": True,
    }
    if args.filter:
        body["query"]["bool"]["must"] = [{"query_string": {"query": args.filter}}]
    req = urllib.request.Request(
        f"{url}/{INDEXES[args.index]}/_search",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": "Basic " + base64.b64encode(
                     f"{user}:{password}".encode()).decode()})
    with urllib.request.urlopen(req, timeout=60, context=_ctx()) as resp:
        hits = json.load(resp)["hits"]["hits"]

    print(f"# {len(hits)} hits in {args.window} (index {INDEXES[args.index]})")
    for h in hits:
        src = h["_source"]
        row = {"_id": h["_id"], "@timestamp": src.get("@timestamp"),
               "event.code": src.get("event.code")}
        for f in FIELDS:
            if f in src:
                row[f] = src[f]
        print(json.dumps(row, ensure_ascii=False))


if __name__ == "__main__":
    sys.exit(main())