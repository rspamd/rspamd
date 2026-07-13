#!/usr/bin/env python3

import socket
import sys

import dummy_killer
import dummy_pidfile

UDP_IP = "127.0.0.1"

if __name__ == "__main__":
    alen = len(sys.argv)
    if alen > 1:
        port = int(sys.argv[1])
    else:
        port = 5005
    pid_path = sys.argv[2] if alen > 2 else dummy_pidfile.pid_path('udp', port)
    sock = socket.socket(socket.AF_INET, # Internet
                         socket.SOCK_DGRAM) # UDP
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((UDP_IP, port))
    dummy_killer.write_pid(pid_path)

    while True:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        print("received message:", data)
        sock.sendto(data, addr)
