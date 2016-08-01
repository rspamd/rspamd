import grp
import os
import os.path
import psutil
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
    return os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "../../")

def get_top_dir():
    if os.environ.get('RSPAMD_TOPDIR'):
        return os.environ['RSPAMD_TOPDIR']

    return get_test_directory() + "/../../"

def get_rspamd():
    if os.environ.get('RSPAMD'):
        return os.environ['RSPAMD']
    dname = get_top_dir()
    return dname + "/src/rspamd"
def get_rspamc():
    if os.environ.get('RSPAMC'):
        return os.environ['RSPAMC']
    dname = get_top_dir()
    return dname + "/src/client/rspamc"
def get_rspamadm():
    if os.environ.get('RSPAMADM'):
        return environ['RSPAMADM']
    dname = get_top_dir()
    return dname + "/src/rspamadm/rspamadm"

def make_temporary_directory():
    return tempfile.mkdtemp()

def read_log_from_position(filename, offset):
    offset = long(offset)
    f = open(filename, 'rb')
    f.seek(offset)
    goo = f.read()
    size = len(goo)
    return [goo, size+offset]

def rspamc(addr, port, filename):
    mboxgoo = b"From MAILER-DAEMON Fri May 13 19:17:40 2016\r\n"
    goo = open(filename, 'rb').read()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, port))
    s.send(b"CHECK RSPAMC/1.0\r\nContent-length: ")
    s.send(str(len(goo+mboxgoo)).encode('utf-8'))
    s.send(b"\r\n\r\n")
    s.send(mboxgoo)
    s.send(goo)
    r = s.recv(2048)
    return r.decode('utf-8')

def scan_file(addr, port, filename):
    return str(urlopen("http://%s:%s/symbols?file=%s" % (addr, port, filename)).read())

def Send_SIGUSR1(pid):
    pid = int(pid)
    os.kill(pid, signal.SIGUSR1)

def set_directory_ownership(path, username, groupname):
    if os.getuid() == 0:
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
    i = 0
    while i < 100:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            assert e.errno == 3
            return
        i += 1
        time.sleep(0.1)
    while i < 200:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError as e:
            assert e.errno == 3
            return
        i += 1
        time.sleep(0.1)
    assert False, "Failed to shutdown process %s" % pid

def shutdown_process_with_children(pid):
    pid = int(pid)
    children = psutil.Process(pid=pid).children(recursive=False)
    shutdown_process(pid)
    for child in children:
        shutdown_process(child.pid)
