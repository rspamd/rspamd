#!/usr/bin/env python3

PID = "/tmp/dummy_p0f.pid"

import os
import sys
import struct
import socket
import socketserver

import dummy_killer

class MyStreamHandler(socketserver.BaseRequestHandler):

    def handle(self):
        S = {
            'bad_query' : 0x0,
            'ok'        : 0x10,
            'no_match'  : 0x20
        }

        OS = {
            'windows' : (b'Windows', b'7 or 8'),
            'linux'   : (b'Linux', b'3.11 and newer')
        }

        self.data = self.request.recv(21).strip()

        if self.server.p0f_status == 'bad_response':
            response = 0
        else:
            response = struct.pack(
                "IbIIIIIIIhbb32s32s32s32s32s32s",
                0x50304602,                       # magic
                S[self.server.p0f_status],        # status
                1568493408,                       # first_seen
                1568493408,                       # last_seen
                1,                                # total_conn
                1,                                # uptime_min
                4,                                # up_mod_days
                1568493408,                       # last_nat
                1568493408,                       # last_chg
                10,                               # distance
                0,                                # bad_sw
                0,                                # os_match_q
                OS[self.server.p0f_os][0],        # os_name
                OS[self.server.p0f_os][1],        # os_flavor
                b'',                              # http_name
                b'',                              # http_flavor
                b'Ethernet or modem',             # link_type
                b''                               # language
            )

        self.request.sendall(response)
        self.request.close()

def cleanup(SOCK):
    if os.path.exists(SOCK):
        try:
            os.unlink(SOCK)
        except OSError:
            print("Could not unlink socket: " + SOCK)

if __name__ == "__main__":
    SOCK = '/tmp/p0f.sock'
    p0f_status = 'ok'
    p0f_os = 'linux'

    alen = len(sys.argv)
    if alen > 1:
        SOCK = sys.argv[1]
        if alen >= 4:
            p0f_os = sys.argv[2]
            p0f_status = sys.argv[3]
        elif alen >= 3:
            p0f_os = sys.argv[2]

    cleanup(SOCK)

    server = socketserver.UnixStreamServer(SOCK, MyStreamHandler, bind_and_activate=False)
    server.allow_reuse_address = True
    server.p0f_status = p0f_status
    server.p0f_os = p0f_os
    server.server_bind()
    server.server_activate()

    dummy_killer.setup_killer(server)
    dummy_killer.write_pid(PID)

    try:
        server.handle_request()
    except socket.error:
        print("Socket closed")

    server.server_close()
    cleanup(SOCK)
