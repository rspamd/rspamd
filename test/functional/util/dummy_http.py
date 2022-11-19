#!/usr/bin/env python3

import http.server
import os
import socket
import socketserver
import sys
import time

import dummy_killer

PORT = 18080
HOST_NAME = '0.0.0.0'

PID = "/tmp/dummy_http.pid"


class MyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_HEAD(self):
        if self.path == "/redirect1":
            self.send_response(301)
            self.send_header("Location", "http://127.0.0.1:"+str(PORT)+"/hello")
        elif self.path == "/redirect2":
            self.send_response(301)
            self.send_header("Location", "http://127.0.0.1:"+str(PORT)+"/redirect1")
        elif self.path == "/redirect3":
            self.send_response(301)
            self.send_header("Location", "http://127.0.0.1:"+str(PORT)+"/redirect4")
        elif self.path == "/redirect4":
            self.send_response(301)
            self.send_header("Location", "http://127.0.0.1:"+str(PORT)+"/redirect3")
        else:
            self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.log_message("to be closed: " + repr(self.close_connection))

    def do_GET(self):
        """Respond to a GET request."""
        response = b"hello world"
        if self.path == "/empty":
            self.finish()
            return

        if self.path == "/timeout":
            time.sleep(2)

        if self.path == "/error_403":
            self.send_response(403)
        else:
            self.send_response(200)

        if self.path == "/content-length":
            self.send_header("Content-Length", str(len(response)))

        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(response)
        self.log_message("to be closed: %d, headers: %s, conn:'%s'" % (self.close_connection, str(self.headers), self.headers.get('Connection', "").lower()))

        conntype = self.headers.get('Connection', "").lower()
        if conntype != 'keep-alive':
            self.close_connection = True

        self.log_message("ka:'%s', pv:%s[%s]" % (str(conntype == 'keep-alive'), str(self.protocol_version >= "HTTP/1.1"), self.protocol_version))


    def do_POST(self):
        """Respond to a POST request."""
        response = b"hello post"
        content_length = int(self.headers.get('Content-Length', "0")) or 0
        if content_length > 0:
            _ = self.rfile.read(content_length)
        if self.path == "/empty":
            self.finish()
            return

        if self.path == "/timeout":
            time.sleep(2)

        if self.path == "/error_403":
            self.send_response(403)
        else:
            self.send_response(200)
        if self.path == "/map-simple":
            response = b"hello map"

        self.send_header("Content-Length", str(len(response)))
        conntype = self.headers.get('Connection', "").lower()
        if conntype != 'keep-alive':
            self.close_connection = True
        else:
            self.send_header("Connection", "keep-alive")

        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(response)
        self.log_message("to be closed: %d, headers: %s, conn:'%s'" % (self.close_connection, str(self.headers), self.headers.get('Connection', "").lower()))
        self.log_message("ka:'%s', pv:%s[%s]" % (str(conntype == 'keep-alive'), str(self.protocol_version >= "HTTP/1.1"), self.protocol_version))


class ThreadingSimpleServer(socketserver.ThreadingMixIn,
                   http.server.HTTPServer):
    def __init__(self):
        self.allow_reuse_address = True
        self.timeout = 1
        http.server.HTTPServer.__init__(self, (HOST_NAME, PORT), MyHandler)

    def run(self):
        dummy_killer.write_pid(PID)
        try:
            while 1:
                sys.stdout.flush()
                server.handle_request()
        except KeyboardInterrupt:
            print("Interrupt")
        except socket.error:
            print("Socket closed")

    def stop(self):
        self.keep_running = False
        self.server_close()


if __name__ == '__main__':
    server = ThreadingSimpleServer()

    dummy_killer.setup_killer(server, server.stop)

    server.run()
