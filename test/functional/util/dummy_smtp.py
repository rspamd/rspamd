#!/usr/bin/env python3
# Dummy SMTP listener for mx_check verify_greeting / send_quit tests.
#
# Modes:
#   silent          - accept the TCP connection and never write a banner.
#                     Exercises the read-timeout path (-> MX_TIMEOUT_READ).
#   error           - send a 5xx code, no banner negotiation (-> MX_ERROR).
#   messy           - send a non-SMTP-shaped line so banner parsing fails
#                     (-> MX_INVALID).
#   greeting_single - send a single-line "220 hello" banner. Used to verify
#                     the no-send_quit path: rspamd should fire MX_GOOD and
#                     close without sending anything. The dummy waits briefly
#                     after the banner; if the client transmits anything it's
#                     recorded as UNEXPECTED_QUIT, otherwise OK_NO_QUIT.
#   greeting_multi  - send a multi-line 220 banner with --between-wait
#                     between lines. Detects whether QUIT arrives between
#                     lines (QUIT_BEFORE_FINAL), after the final line
#                     (QUIT_AFTER_FINAL), or not at all (NO_QUIT / EOF_BEFORE
#                     _FINAL when the client closes early). Pair with
#                     --between-wait < read_timeout for a healthy run and
#                     --between-wait > read_timeout to exercise the slow-
#                     second-line MX_TIMEOUT_READ case.
#
# CLI:
#   --port PORT          (default 11125)
#   --mode MODE          (default silent)
#   --host HOST          (default 127.0.0.1)
#   --pre-wait SEC       (default 0.0)  delay before sending anything
#   --between-wait SEC   (default 0.2)  greeting_multi: wait between lines
#                                        (also the early-QUIT detection window)
#   --status-file PATH   (optional)     write final status here for the test
#                                        to verify QUIT timing out-of-band
#   --pid-file PATH      (default /tmp/dummy_smtp_<mode>.pid)

import argparse
import os
import select
import socket
import socketserver
import sys
import time

import dummy_killer


def _write_status(path, value):
    if not path:
        return
    try:
        with open(path, "w") as f:
            f.write(value + "\n")
    except Exception:
        pass


def _make_handler(args):

    class Handler(socketserver.BaseRequestHandler):

        def handle(self):
            if args.pre_wait > 0:
                time.sleep(args.pre_wait)

            if args.mode == "silent":
                try:
                    time.sleep(30)
                except Exception:
                    pass
                return

            if args.mode == "error":
                self.request.sendall(b"550 not interested\r\n")
                return

            if args.mode == "messy":
                self.request.sendall(
                    b"This is a messy message to you, no smtp here\r\n")
                return

            if args.mode == "greeting_single":
                # Send a CONTINUATION banner line on purpose (220-, not "220 ")
                # so the test exercises mx_check's send_quit=false branch:
                # rspamd should fire MX_GOOD off the first line without
                # waiting for a continuation. Then hold the connection well
                # past read_timeout without sending anything more -- a
                # regression that re-queued the read would surface as
                # MX_TIMEOUT_READ from rspamd's side.
                self.request.sendall(b"220-Greeting\r\n")
                ready, _, _ = select.select([self.request], [], [], 2.0)
                if ready:
                    try:
                        data = self.request.recv(1024)
                    except Exception:
                        data = b""
                    if data:
                        _write_status(args.status_file, "UNEXPECTED_QUIT")
                    else:
                        _write_status(args.status_file, "OK_NO_QUIT")
                else:
                    _write_status(args.status_file, "NO_CLOSE")
                return

            if args.mode == "greeting_multi":
                self.request.sendall(b"220-Greeting\r\n")
                # Wait between lines. Any data here means QUIT was sent
                # before the banner finished.
                ready, _, _ = select.select([self.request], [], [],
                                            args.between_wait)
                if ready:
                    try:
                        data = self.request.recv(1024)
                    except Exception:
                        data = b""
                    if data:
                        _write_status(args.status_file, "QUIT_BEFORE_FINAL")
                    else:
                        # Peer closed before the final line was sent (e.g.
                        # rspamd timed out and closed mid-banner).
                        _write_status(args.status_file, "EOF_BEFORE_FINAL")
                    return
                # Final line; under correct mx_check behaviour QUIT should
                # follow shortly.
                try:
                    self.request.sendall(b"220 Now you can speak\r\n")
                except Exception:
                    _write_status(args.status_file, "EOF_BEFORE_FINAL")
                    return
                self.request.settimeout(2)
                try:
                    data = self.request.recv(1024)
                except Exception:
                    data = b""
                if data:
                    _write_status(args.status_file, "QUIT_AFTER_FINAL")
                    try:
                        self.request.sendall(b"221 bye\r\n")
                    except Exception:
                        pass
                else:
                    _write_status(args.status_file, "NO_QUIT")
                return

    return Handler


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=11125)
    parser.add_argument("--mode",
                        choices=["silent", "error", "messy",
                                 "greeting_single", "greeting_multi"],
                        default="silent")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--pre-wait", dest="pre_wait", type=float, default=0.0)
    parser.add_argument("--between-wait", dest="between_wait", type=float,
                        default=0.2)
    parser.add_argument("--status-file", dest="status_file", default=None)
    parser.add_argument("--pid-file", dest="pid_file", default=None)
    args = parser.parse_args()

    if not args.pid_file:
        args.pid_file = "/tmp/dummy_smtp_%s.pid" % args.mode

    # Clear stale status file from a previous run so tests don't trip on it.
    if args.status_file and os.path.exists(args.status_file):
        try:
            os.remove(args.status_file)
        except Exception:
            pass

    handler = _make_handler(args)
    server = socketserver.TCPServer((args.host, args.port), handler,
                                    bind_and_activate=False)
    server.allow_reuse_address = True
    server.server_bind()
    server.server_activate()

    dummy_killer.setup_killer(server)
    dummy_killer.write_pid(args.pid_file)

    try:
        server.serve_forever()
    except socket.error:
        print("Socket closed")
    server.server_close()
