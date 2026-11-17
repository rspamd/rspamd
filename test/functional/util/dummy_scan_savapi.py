#!/usr/bin/env python3
"""Dummy SAVAPI for the savapi scanner: one dialog, then exit.

Usage: dummy_scan_savapi.py <port> <mode> [<pid file>]

Modes:
  clean     the file is clean
  infected  the file name in the reply contains "200", the verdict is a virus;
            informational (401) and repairable (420) lines come before the 310
  repair    only a 420 (infected, repairable) line precedes the final 319
  banner    the greeting is not a SAVAPI one
"""

import socket
import socketserver
import sys

import dummy_killer
import dummy_pidfile


def read_line(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


class MyTCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        mode = self.server.mode
        if mode == "banner":
            self.request.sendall(b"421 Service not available\n")
            self.request.close()
            return
        self.request.sendall(b"100 SAVAPI:4.0\n")
        read_line(self.request)  # SET PRODUCT
        self.request.sendall(b"100 PRODUCT:0\n")
        line = read_line(self.request)  # SCAN <file>
        fname = line.strip().split(b" ", 1)[-1]
        if mode == "infected":
            # "200" inside a file name must not be taken for a status code
            self.request.sendall(b"401 scan started\n"
                                 b"420 /tmp/200-210-file.tmp <<< Eicar-Repairable ; virus ; 7\n"
                                 b"310 /tmp/200-210-file.tmp <<< Eicar-Test-File ; virus ; 12\n"
                                 b"319 /tmp/200-210-file.tmp\n")
        elif mode == "repair":
            self.request.sendall(b"420 /tmp/repairable.tmp <<< Eicar-Repairable ; virus ; 7\n"
                                 b"319 /tmp/repairable.tmp\n")
        else:
            self.request.sendall(b"200 " + fname + b" clean\n")
        read_line(self.request)  # QUIT
        self.request.close()


if __name__ == "__main__":
    HOST = "127.0.0.1"

    alen = len(sys.argv)
    port = int(sys.argv[1]) if alen > 1 else 4444
    mode = sys.argv[2] if alen > 2 else "clean"
    pid_path = sys.argv[3] if alen > 3 else dummy_pidfile.pid_path('savapi', port)

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
