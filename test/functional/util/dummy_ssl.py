#!/usr/bin/env python3
"""A TLS (and STARTTLS) server for the lua_tcp tests.

usage: dummy_ssl.py pemfile [port] [pid_path]

A connection that starts with a TLS ClientHello is a TLS connection from the
very beginning. Anything else is a plaintext connection that is upgraded when
the client asks for it (see below). After the handshake every chunk the client
sends is answered with `hello\n`, unless it is a command:

  BIG <n>\n    send n bytes in ONE write (the last byte is a newline), then keep
               the connection open and idle
  SILENT\n     never answer, keep the connection open

Plaintext commands (a line, `\r\n` terminated):

  STARTTLS        answer `READY`, then do the handshake
  STARTTLS-GREET  the same, and send `greeting\n` right after the handshake
  STARTTLS-INJECT answer `READY` and a line of extra plaintext in the same
                  write, do NOT do the handshake
  STARTTLS-GARBAGE answer `READY` and, a moment later, bytes that are not
                  TLS: a client that starts its handshake after that fails
                  at once

The server is bounded: it serves a limited number of connections, every
connection has a deadline, and the usual alarm based killer is installed.
"""

import os
import signal
import socket
import socketserver
import ssl
import sys
import threading
import time

import dummy_killer
import dummy_pidfile

DEFAULT_PORT = 14433
HOST_NAME = '127.0.0.1'
MAX_CONNECTIONS = 1000
CONN_DEADLINE = 20
ALARM = 300


def log(msg):
    print(msg, flush=True)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(1)
        first = None
        deadline = time.time() + CONN_DEADLINE

        # A client that connects and says nothing (a silent plaintext peer)
        # is kept until the deadline
        while first is None and time.time() < deadline:
            try:
                first = sock.recv(1, socket.MSG_PEEK)
            except socket.timeout:
                continue
            except socket.error:
                return

        if first is None:
            return

        if not first:
            # A readiness probe: connected and closed without a word
            return

        if first == b'\x16':
            tls = self.server.make_tls(sock)
            if tls is None:
                return
            self.serve_tls(tls)
        else:
            self.serve_plain(sock)

    def serve_plain(self, sock):
        data = b''
        deadline = time.time() + CONN_DEADLINE
        sock.settimeout(1)
        while b'\r\n' not in data and time.time() < deadline:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                # A silent client: wait for it until the deadline
                continue
            except socket.error:
                return
            if not chunk:
                return
            data += chunk

        cmd = data.split(b'\r\n', 1)[0]
        log('plain command: {!r}'.format(cmd))

        if cmd == b'STARTTLS-INJECT':
            # The extra plaintext follows the ready line in the same segment
            sock.sendall(b'READY\r\nINJECTED\r\n')
            time.sleep(3)
            return

        if cmd == b'STARTTLS-GARBAGE':
            sock.sendall(b'READY\r\n')
            time.sleep(0.1)
            sock.sendall(b'this is not a TLS record at all\r\n' * 4)
            time.sleep(3)
            return

        if cmd in (b'STARTTLS', b'STARTTLS-GREET'):
            sock.sendall(b'READY\r\n')
            tls = self.server.make_tls(sock)
            if tls is None:
                return
            if cmd == b'STARTTLS-GREET':
                tls.sendall(b'greeting\n')
            self.serve_tls(tls)

    def serve_tls(self, tls):
        tls.settimeout(1)
        deadline = time.time() + CONN_DEADLINE

        while time.time() < deadline:
            try:
                data = tls.recv(6000000)
            except socket.timeout:
                continue
            except (socket.error, ssl.SSLError):
                return

            if not data:
                return

            log('tls data: {!r}'.format(data[:40]))

            if data.startswith(b'BIG '):
                size = int(data.split(b'\n')[0].split()[1])
                # One write: for sizes below the record limit it is one record
                tls.sendall(b'x' * (size - 1) + b'\n')
            elif data.startswith(b'SILENT'):
                pass
            else:
                time.sleep(0.1)
                tls.sendall(b'hello\n')


class SSLServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, certfile):
        super().__init__(server_address, Handler)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile=certfile)
        self.count = 0

    def make_tls(self, sock):
        try:
            sock.settimeout(10)
            return self.ctx.wrap_socket(sock, server_side=True)
        except (socket.error, ssl.SSLError) as e:
            log('handshake failed: {}'.format(e))
            return None

    def verify_request(self, request, client_address):
        self.count += 1
        if self.count > MAX_CONNECTIONS:
            # The bound is reached: leave soon, after the last client is served
            threading.Timer(3.0, os._exit, [0]).start()
        return True

    def run(self, pid_path):
        dummy_killer.write_pid(pid_path)
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            print("Interrupt")
        except socket.error as e:
            print("Socket closed {}".format(e))
        finally:
            self.server_close()


if __name__ == '__main__':
    # argv: pemfile [port] [pid_path]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    pid_path = sys.argv[3] if len(sys.argv) > 3 else dummy_pidfile.pid_path('ssl', port)
    server = SSLServer((HOST_NAME, port), sys.argv[1])
    dummy_killer.setup_killer(server)
    # The suite runs longer than the default alarm
    signal.alarm(ALARM)
    server.run(pid_path)
