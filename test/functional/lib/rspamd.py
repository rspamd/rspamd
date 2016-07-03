import grp
import os
import os.path
import pwd
import shutil
import signal
import socket
import string
import sys
import tempfile
import time

if sys.version_info > (3,):
    long = int
try:
    from urllib.request import urlopen
except:
    from urllib2 import urlopen

def cleanup_temporary_directory(directory):
    shutil.rmtree(directory)

def encode_filename(filename):
    return "".join(['%%%0X' % ord(b) for b in filename])

def get_test_directory():
    return os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "../..")

def make_temporary_directory():
    return tempfile.mkdtemp()

def process_should_exist(pid):
    pid = int(pid)
    os.kill(pid, 0)

def read_log_from_position(filename, offset):
    offset = long(offset)
    f = open(filename, 'rb')
    f.seek(offset)
    goo = f.read()
    size = len(goo)
    return [goo, size+offset]

def scan_file(addr, port, filename):
    return str(urlopen("http://%s:%s/symbols?%s" % (addr, port, filename)).read())

def Send_SIGUSR1(pid):
    pid = int(pid)
    os.kill(pid, signal.SIGUSR1)

def set_directory_ownership(path, username, groupname):
    uid=pwd.getpwnam(username).pw_uid
    gid=grp.getgrnam(groupname).gr_gid
    os.chown(path, uid, gid)

def spamc(addr, port, filename):
    goo = open(filename, 'rb').read()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, port))
    s.send(b"SYMBOLS SPAMC/1.0\r\nContent-length: ")
    s.send(str(len(goo)).encode('utf-8'))
    s.send(b"\r\n\r\n")
    s.send(goo)
    s.shutdown(socket.SHUT_WR)
    r = s.recv(2048)
    return r.decode('utf-8')

def update_dictionary(a, b):
    a.update(b)
    return a

def shutdown_process(pid):
    pid = int(pid)
    process_should_exist(pid)
    i = 0
    while i < 5:
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.1)
        except:
            break
    if i >= 5:
        while True:
            try:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
            except:
                break
