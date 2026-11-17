#!/usr/bin/env python3
"""A tiny TCP server that answers a request with a few bytes and then resets
the connection (RST instead of FIN), for testing how a client reports a reset
as opposed to a clean end of stream.

usage: dummy_tcp_reset.py [port] [pid_path]

It serves a bounded number of requests and exits by itself; the usual alarm
based killer is installed as well.
"""

import socket
import signal
import socketserver
import struct
import sys
import time

import dummy_killer
import dummy_pidfile

DEFAULT_PORT = 18081
HOST_NAME = '127.0.0.1'
# Every symbol of lua/tcp.lua that talks to this port runs in every scan
MAX_CONNECTIONS = 500
# The suite runs longer than the default alarm
ALARM = 300


class ResetHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            data = self.request.recv(4096)
        except socket.error:
            return

        if not data:
            # A readiness probe: connected and closed without a request
            return

        self.request.sendall(b'abc')
        time.sleep(0.2)
        # SO_LINGER with a zero timeout turns close() into a reset
        self.request.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                struct.pack('ii', 1, 0))


class ResetServer(socketserver.TCPServer):
    allow_reuse_address = True

    def shutdown_request(self, request):
        # The default sends a FIN first, which would hide the reset
        self.close_request(request)

    def run(self, pid_path):
        dummy_killer.write_pid(pid_path)
        try:
            for _ in range(MAX_CONNECTIONS):
                self.handle_request()
        except KeyboardInterrupt:
            print("Interrupt")
        except socket.error as e:
            print("Socket closed {}".format(e))
        finally:
            self.server_close()


if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    pid_path = sys.argv[2] if len(sys.argv) > 2 else dummy_pidfile.pid_path('tcp_reset', port)
    server = ResetServer((HOST_NAME, port), ResetHandler)
    dummy_killer.setup_killer(server)
    signal.alarm(ALARM)
    server.run(pid_path)
