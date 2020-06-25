#!/usr/bin/env python3

import os
import signal
import socket
import socketserver
import sys

import dummy_killer

PID = "/tmp/dummy_fprot.pid"

class MyTCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        self.data = self.request.recv(1024).strip()
        if self.server.foundvirus:
            self.request.sendall(b"1 <infected: EICAR_Test_File> FOO->bar\n")
        else:
            self.request.sendall(b"0 <clean> FOO\n")
        self.request.close()

if __name__ == "__main__":

    HOST = "localhost"

    alen = len(sys.argv)
    if alen > 1:
        port = int(sys.argv[1])
        if alen >= 4:
            PID = sys.argv[3]
            foundvirus = bool(sys.argv[2])
        elif alen >= 3:
            foundvirus = bool(sys.argv[2])
        else:
            foundvirus = False
    else:
        port = 10200
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
