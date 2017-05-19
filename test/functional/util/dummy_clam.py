#!/usr/bin/env python

PID = "/tmp/dummy_clamav.pid"

import os
import sys
try:
    import SocketServer as socketserver
except:
    import socketserver
import signal

class MyTCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        os.remove(PID)
        self.data = self.request.recv(1024).strip()
        if self.server.foundvirus:
            self.request.sendall(b"stream: Eicar-Test-Signature FOUND\0")
        else:
            self.request.sendall(b"stream: OK\0")
        self.request.close()

if __name__ == "__main__":
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    signal.alarm(5)

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
    open(PID, 'w').close()
    server.handle_request()
    server.server_close()
    os.exit(0)
