#!/usr/bin/env python3
"""Dummy spamd for the SpamAssassin scanner: one request, one reply, exit.

Usage: dummy_scan_spamd.py <port> <mode> [<pid file>]

Modes:
  clean     status line "No", score 0
  spam      status line "Yes", the reply is sent in two chunks
  error     "SPAMD/1.1 76 ..." without any headers
  nostatus  "SPAMD/1.1 0 EX_OK" and headers without X-Spam-Status
"""

import socket
import socketserver
import sys
import time

import dummy_killer
import dummy_pidfile


def read_request(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    length = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    while len(body) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    return data


def reply(mode, headers):
    # spamd answers with its own status block followed by the message headers
    payload = headers.encode()
    return ("SPAMD/1.1 0 EX_OK\r\nContent-length: %d\r\n\r\n" % len(payload)).encode(), payload


class MyTCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        read_request(self.request)
        mode = self.server.mode
        if mode == "error":
            self.request.sendall(b"SPAMD/1.1 76 Bad header line: X-Whatever\r\n")
        elif mode == "nostatus":
            head, payload = reply(mode, "Subject: nothing to see\r\n\r\n")
            self.request.sendall(head + payload)
        elif mode == "spam":
            head, payload = reply(mode, "Received: from nowhere\r\n"
                                  "X-Spam-Status: Yes, score=9.5 required=5.0 tests=FOO_BAR,\r\n"
                                  "\tBAZ_QUX autolearn=no autolearn_force=no version=3.4.6\r\n\r\n")
            # The status line only arrives with the second chunk
            self.request.sendall(head)
            time.sleep(0.3)
            self.request.sendall(payload)
        else:
            head, payload = reply(mode, "X-Spam-Status: No, score=0.0 required=5.0 tests=none "
                                  "autolearn=no\r\n\r\n")
            self.request.sendall(head + payload)
        self.request.close()


if __name__ == "__main__":
    HOST = "127.0.0.1"

    alen = len(sys.argv)
    port = int(sys.argv[1]) if alen > 1 else 7830
    mode = sys.argv[2] if alen > 2 else "clean"
    pid_path = sys.argv[3] if alen > 3 else dummy_pidfile.pid_path('spamd', port)

    server = socketserver.TCPServer((HOST, port), MyTCPHandler, bind_and_activate=False)
    server.allow_reuse_address = True
    server.mode = mode
    server.server_bind()
    server.server_activate()

    dummy_killer.setup_killer(server)
    dummy_killer.write_pid(pid_path)

    try:
        server.handle_request()
    except socket.error:
        print("Socket closed")

    server.server_close()
