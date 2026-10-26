#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dummy PeekabooAV-like server used to test lualib/lua_scanners/peekaboo.lua.

Emulates the two endpoints peekaboo.lua talks to:

  POST /v1/scan          -> 200 {"job_id": "1"}
  GET  /v1/report/<id>   -> 404 on the first poll (mimics an in-progress
                             sandbox analysis), then a JSON result body
                             (per --mode) on every subsequent poll.

The 404-then-result behaviour is intentionally process-global rather than
keyed by job_id: each test case starts a fresh dummy instance, so the first
`Scan File` call is expected to observe PEEKABOO_IN_PROCESS (report poll #1
-> 404) and a second `Scan File` call (fresh job_id, same dummy process,
report poll #2) observes the final --mode result.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

import dummy_killer
import dummy_pidfile

RESULTS = {
    'bad': {'result': 'bad', 'reason': 'sandbox detected malicious behaviour'},
    'good': {'result': 'good', 'reason': 'whitelisted sample'},
    'failed': {'result': 'failed', 'reason': 'sandbox analysis failed'},
    'unknown': {'result': 'unknown', 'reason': 'no threat found'},
}


class PeekabooHandler(BaseHTTPRequestHandler):
    def _send_json(self, code, obj):
        body = json.dumps(obj).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', '0'))
        if length > 0:
            self.rfile.read(length)

        if self.path != self.server.url_check:
            self.send_response(404)
            self.end_headers()
            return

        self._send_json(200, {'job_id': '1'})

    def do_GET(self):
        prefix = self.server.url_report + '/'
        if not self.path.startswith(prefix):
            self.send_response(404)
            self.end_headers()
            return

        self.server.report_calls += 1
        if self.server.report_calls == 1:
            # First poll: sandbox analysis still running.
            self.send_response(404)
            self.end_headers()
            return

        self._send_json(200, RESULTS[self.server.mode])

    def log_message(self, fmt, *args):
        # Keep test output quiet.
        return


if __name__ == "__main__":
    alen = len(sys.argv)
    port = int(sys.argv[1]) if alen > 1 else 8100
    mode = sys.argv[2] if alen > 2 else 'bad'
    pid_path = sys.argv[3] if alen > 3 else dummy_pidfile.pid_path('peekaboo', port)

    server = HTTPServer(('127.0.0.1', port), PeekabooHandler)
    server.url_check = '/v1/scan'
    server.url_report = '/v1/report'
    server.mode = mode
    server.report_calls = 0

    dummy_killer.setup_killer(server)
    dummy_killer.write_pid(pid_path)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
