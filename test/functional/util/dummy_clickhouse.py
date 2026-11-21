#!/usr/bin/env python3
"""Stub of the ClickHouse HTTP interface for the clickhouse plugin tests.

It answers the schema version query of the plugin with a configurable
version and the system.columns query of the profile gate with a
configurable number of profile columns, accepts every other statement
and INSERT with an empty 200 reply and appends every request it sees to a
file, one JSON object per line:

  {"kind": "insert", "query": "<INSERT ... FORMAT TabSeparated>", "body": "<decoded rows>"}
  {"kind": "select", "sql": "<statement>"}
  {"kind": "statement", "sql": "<statement>"}

The version is fixed: the stub does not apply migrations.
"""

import asyncio
import argparse
import json
import sys
import threading
import traceback

import dummy_killer
import tornado.httpserver
import tornado.web

LOCK = threading.Lock()


class Handler(tornado.web.RequestHandler):
    def initialize(self, version, profile_columns, out):
        self.version = version
        self.profile_columns = profile_columns
        self.out = out

    def record(self, obj):
        with LOCK:
            with open(self.out, "a", encoding="utf-8") as f:
                f.write(json.dumps(obj) + "\n")

    def handle(self):
        body = self.request.body.decode("utf-8", errors="replace")
        query = self.get_query_argument("query", default=None)
        self.set_header("Content-Type", "text/plain; charset=UTF-8")

        if self.request.path == "/ping":
            self.write("Ok.\n")
            return

        if query is not None:
            # INSERT: the statement is in the URL, the rows are the body
            self.record({"kind": "insert", "query": query, "body": body})
            return

        sql = body.strip()
        upper = sql.upper()
        fmt = self.get_query_argument("default_format", default="")
        if upper.startswith("SELECT MAX(VERSION)"):
            self.record({"kind": "select", "sql": sql})
            self.write(json.dumps({"v": self.version}) + "\n")
        elif upper.startswith("SELECT COUNT()") and "SYSTEM.COLUMNS" in upper:
            self.record({"kind": "select", "sql": sql})
            self.write(json.dumps({"c": self.profile_columns}) + "\n")
        elif upper.startswith("SELECT") or upper.startswith("EXISTS"):
            self.record({"kind": "select", "sql": sql})
            if upper.startswith("EXISTS"):
                self.write(json.dumps({"result": 1}) + "\n")
        else:
            self.record({"kind": "statement", "sql": sql})
            if fmt == "JSON":
                self.write(json.dumps({"meta": [], "data": [], "rows": 0}))

    get = handle
    post = handle


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", "-b", default="127.0.0.1")
    parser.add_argument("--port", "-p", type=int, default=18123)
    parser.add_argument("--pidfile", "-pf")
    parser.add_argument("--version", "-v", type=int, default=13,
                        help="schema version reported to SELECT MAX(Version)")
    parser.add_argument("--profile-columns", "-c", type=int, default=-1,
                        help="number of profile columns reported to the system.columns "
                             "query; by default 5 from schema version 13 on, else 0")
    parser.add_argument("--out", "-o", required=True,
                        help="file to append the requests to")
    args = parser.parse_args()

    if args.profile_columns < 0:
        args.profile_columns = 5 if args.version >= 13 else 0

    # Start with an empty record
    open(args.out, "w").close()

    app = tornado.web.Application(
        [(r"/.*", Handler, dict(version=args.version,
                                profile_columns=args.profile_columns, out=args.out))])
    # The plugin gzips its requests when use_gzip is set
    server = tornado.httpserver.HTTPServer(app, decompress_request=True)
    server.bind(args.port, args.bind)
    server.start(1)

    # After a successful bind
    if args.pidfile:
        dummy_killer.write_pid(args.pidfile)

    print("dummy_clickhouse.py: listening on %s:%d, schema version %d" %
          (args.bind, args.port, args.version), file=sys.stderr)
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print("dummy_clickhouse.py: FATAL ERROR: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
