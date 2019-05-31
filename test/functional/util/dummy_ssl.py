#!/usr/bin/env python

import SocketServer
import dummy_killer

import time
import os
import sys
import socket
import ssl

PORT = 14433
HOST_NAME = '127.0.0.1'

PID = "/tmp/dummy_ssl.pid"

class SSLTCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        while data:
            print "{} wrote:".format(self.client_address[0])
            print data
            self.request.sendall(data)
            data = self.request.recv(1024)

class SSL_TCP_Server(SocketServer.TCPServer):
    def __init__(self,
                 server_address,
                 RequestHandlerClass,
                 certfile,
                 keyfile,
                 ssl_version=ssl.PROTOCOL_TLSv1,
                 bind_and_activate=True):
        self.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, server_address,
                                        RequestHandlerClass, bind_and_activate)
        self.certfile = certfile
        self.keyfile = keyfile
        self.ssl_version = ssl_version
        #self.timeout = 1

    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket(newsocket,
                                     server_side=True,
                                     certfile = self.certfile,
                                     keyfile = self.keyfile,
                                     ssl_version = self.ssl_version)
        return connstream, fromaddr

    def run(self):
        dummy_killer.write_pid(PID)
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            print "Interrupt"
        except socket.error as e:
            print "Socket closed {}".format(e)

    def stop(self):
        self.keep_running = False
        self.server_close()

class SSL_ThreadingTCPServer(SocketServer.ThreadingMixIn, SSL_TCP_Server): pass

if __name__ == '__main__':
    server = SSL_ThreadingTCPServer((HOST_NAME, PORT), SSLTCPHandler, sys.argv[1], sys.argv[1])
    dummy_killer.setup_killer(server, server.stop)
    server.run()
