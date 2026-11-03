#!/usr/bin/env python3

import socket
import socketserver
import sys

import dummy_killer
import dummy_pidfile

class MyTCPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        # razor.lua's razor_check compares tostring(data) to the exact
        # strings "spam"/"ham" (see lualib/lua_scanners/razor.lua) - no
        # trailing newline, connection closed right after the reply.
        self.data = self.request.recv(65536)
        if self.server.spam:
            self.request.sendall(b"spam")
        else:
            self.request.sendall(b"ham")
        self.request.close()

if __name__ == "__main__":
    HOST = "127.0.0.1"

    alen = len(sys.argv)
    if alen > 1:
        port = int(sys.argv[1])
        if alen >= 3:
            spam = bool(sys.argv[2])
        else:
            spam = False
    else:
        port = 10045
        spam = False

    server = socketserver.TCPServer((HOST, port), MyTCPHandler, bind_and_activate=False)
    server.allow_reuse_address = True
    server.spam = spam
    server.server_bind()
    server.server_activate()

    dummy_killer.setup_killer(server)
    pid_path = sys.argv[3] if alen > 3 else dummy_pidfile.pid_path('razor', port)
    dummy_killer.write_pid(pid_path)

    try:
        server.handle_request()
    except socket.error:
        print("Socket closed")

    server.server_close()
