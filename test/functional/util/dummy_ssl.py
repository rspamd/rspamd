#!/usr/bin/env python3

import os
import socket
import ssl
import sys
import time

import dummy_killer
import socketserver

PORT = 14433
HOST_NAME = '127.0.0.1'

PID = "/tmp/dummy_ssl.pid"

class SSLTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        time.sleep(0.5)
        data = self.request.recv(6000000)
        while data:
            print("{} wrote:".format(self.client_address[0]))
            print(data)
            time.sleep(0.1)
            self.request.sendall(b'hello\n')
            time.sleep(0.1)
            data = self.request.recv(6000000)

class SSL_TCP_Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self,
                 server_address,
                 RequestHandlerClass,
                 certfile,
                 keyfile,
                 bind_and_activate=True):
        self.allow_reuse_address = True
        super().__init__(server_address, RequestHandlerClass, False)
        self.timeout = 1
        ctx = ssl.create_default_context()
        ctx.load_cert_chain(certfile=certfile)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.socket = ctx.wrap_socket(self.socket, server_side=True)
        if (bind_and_activate):
            self.server_bind()
            self.server_activate()

    def run(self):
        dummy_killer.write_pid(PID)
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            print("Interrupt")
        except socket.error as e:
            print("Socket closed {}".format(e))
        finally:
            self.server_close()

    def stop(self):
        self.keep_running = False
        self.server_close()

if __name__ == '__main__':
    server = SSL_TCP_Server((HOST_NAME, PORT), SSLTCPHandler, sys.argv[1], sys.argv[1])
    dummy_killer.setup_killer(server, server.stop)
    server.run()
