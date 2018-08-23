#!/usr/bin/env python

import BaseHTTPServer
import time
import os
import sys
import signal

PORT = 18080
HOST_NAME = '127.0.0.1'

PID = "/tmp/dummy_http.pid"


class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        """Respond to a GET request."""
        if self.path == "/empty":
            self.finish()
            return

        if self.path == "/timeout":
            time.sleep(2)

        if self.path == "/error_403":
            self.send_response(403)
        else:
            self.send_response(200)

        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("hello world")

    def do_POST(self):
        """Respond to a GET request."""
        if self.path == "/empty":
            self.finish()
            return

        if self.path == "/timeout":
            time.sleep(2)

        if self.path == "/error_403":
            self.send_response(403)
        else:
            self.send_response(200)

        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write("hello post")


class MyHttp(BaseHTTPServer.HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=False):
        BaseHTTPServer.HTTPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        self.keep_running = True

    def run(self):
        self.server_bind()
        self.server_activate()

        with open(PID, 'w+') as f:
            f.write(str(os.getpid()))
            f.close()

        while self.keep_running:
            try:
                self.handle_request()
            except Exception:
                pass

    def stop(self):
        self.keep_running = False
        self.server_close()


if __name__ == '__main__':
    server_class = BaseHTTPServer.HTTPServer
    httpd = MyHttp((HOST_NAME, PORT), MyHandler)
    httpd.allow_reuse_address = True
    httpd.timeout = 1

    def alarm_handler(signum, frame):
        httpd.stop()

    signal.signal(signal.SIGALRM, alarm_handler)
    signal.signal(signal.SIGTERM, alarm_handler)
    signal.alarm(10)

    try:
        httpd.run()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
