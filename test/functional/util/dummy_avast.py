#!/usr/bin/env python3

PID = "/tmp/dummy_avast.pid"

import os
import socket
import socketserver
import sys

import dummy_killer

class MyTCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        self.request.sendall(b"220 DAEMON\r\n")
        self.data = self.request.recv(1024).strip()
        self.request.sendall(b"210 SCAN DATA\r\n")
        if self.server.foundvirus:
            self.request.sendall(b"SCAN /some/path/malware/xpaj/00908235ee9e267fa2f4c83fb4304c63af976cbc\t[L]0.0\t0 Eicar\\ [Heur]\r\n")
        else:
            self.request.sendall(b"SCAN /some/path/malware/xpaj/00908235ee9e267fa2f4c83fb4304c63af976cbc\t[+]\r\n")
        self.request.sendall(b"200 SCAN OK\r\n")
        self.request.close()

if __name__ == "__main__":
    HOST = "localhost"

    alen = len(sys.argv)
    if alen > 1:
        port = int(sys.argv[1])
        if alen >= 3:
            foundvirus = bool(sys.argv[2])
        else:
            foundvirus = False
    else:
        port = 3310
        foundvirus = False

    server = socketserver.TCPServer((HOST, port), MyTCPHandler, bind_and_activate=False)
    server.allow_reuse_address = True
    server.foundvirus = foundvirus
    server.server_bind()
    server.server_activate()

    dummy_killer.setup_killer(server)
    dummy_killer.write_pid(PID)

    try:
        server.handle_request()
    except socket.error:
        print("Socket closed")

    server.server_close()
