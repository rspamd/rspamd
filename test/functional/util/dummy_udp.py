import socket
import sys

UDP_IP = "127.0.0.1"

if __name__ == "__main__":
    alen = len(sys.argv)
    if alen > 1:
        port = int(sys.argv[1])
    else:
        port = 5005
    sock = socket.socket(socket.AF_INET, # Internet
                         socket.SOCK_DGRAM) # UDP
    sock.bind((UDP_IP, port))

    while True:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        print "received message:", data
        sock.sendto(data, addr)