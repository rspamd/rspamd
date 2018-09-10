import demjson
import grp
import os
import os.path
import psutil
import pwd
import re
import shutil
import signal
import socket
import errno
import sys
import tempfile
import time
from robot.libraries.BuiltIn import BuiltIn
from robot.api import logger

if sys.version_info > (3,):
    long = int
try:
    from urllib.request import urlopen
except:
    from urllib2 import urlopen
try:
    import http.client as httplib
except:
    import httplib

def Check_JSON(j):
    d = demjson.decode(j, strict=True)
    assert len(d) > 0
    assert 'error' not in d
    return d

def cleanup_temporary_directory(directory):
    shutil.rmtree(directory)

def save_run_results(directory, filenames):
    current_directory = os.getcwd()
    suite_name = BuiltIn().get_variable_value("${SUITE_NAME}")
    test_name = BuiltIn().get_variable_value("${TEST NAME}")
    if test_name is None:
        # this is suite-level tear down 
        destination_directory = "%s/robot-save/%s" % (current_directory, suite_name)
    else:
        destination_directory = "%s/robot-save/%s/%s" % (current_directory, suite_name, test_name)
    if not os.path.isdir(destination_directory):
        os.makedirs(destination_directory)
    for file in filenames.split(' '):
        source_file = "%s/%s" % (directory, file)
        if os.path.isfile(source_file):
            shutil.copy(source_file, "%s/%s" % (destination_directory, file))
            shutil.copy(source_file, "%s/robot-save/%s.last" % (current_directory, file))

def encode_filename(filename):
    return "".join(['%%%0X' % ord(b) for b in filename])

def get_test_directory():
    return os.path.abspath(os.path.dirname(os.path.realpath(__file__)) + "../../")

def get_top_dir():
    if os.environ.get('RSPAMD_TOPDIR'):
        return os.environ['RSPAMD_TOPDIR']

    return get_test_directory() + "/../../"

def get_install_root():
    if os.environ.get('RSPAMD_INSTALLROOT'):
        return os.path.abspath(os.environ['RSPAMD_INSTALLROOT'])

    return os.path.abspath("../install/")

def get_rspamd():
    if os.environ.get('RSPAMD'):
        return os.environ['RSPAMD']
    if os.environ.get('RSPAMD_INSTALLROOT'):
        return os.environ['RSPAMD_INSTALLROOT'] + "/bin/rspamd"
    dname = get_top_dir()
    return dname + "/src/rspamd"

def get_rspamc():
    if os.environ.get('RSPAMC'):
        return os.environ['RSPAMC']
    if os.environ.get('RSPAMD_INSTALLROOT'):
        return os.environ['RSPAMD_INSTALLROOT'] + "/bin/rspamc"
    dname = get_top_dir()
    return dname + "/src/client/rspamc"

def get_rspamadm():
    if os.environ.get('RSPAMADM'):
        return os.environ['RSPAMADM']
    if os.environ.get('RSPAMD_INSTALLROOT'):
        return os.environ['RSPAMD_INSTALLROOT'] + "/bin/rspamadm"
    dname = get_top_dir()
    return dname + "/src/rspamadm/rspamadm"

def HTTP(method, host, port, path, data=None, headers={}):
    c = httplib.HTTPConnection("%s:%s" % (host, port))
    c.request(method, path, data, headers)
    r = c.getresponse()
    t = r.read()
    s = r.status
    c.close()
    return [s, t]

def make_temporary_directory():
    return tempfile.mkdtemp()

def make_temporary_file():
    return tempfile.mktemp()

def path_splitter(path):
    dirname = os.path.dirname(path)
    basename = os.path.basename(path)
    return [dirname, basename]

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

def TCP_Connect(addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, port))

def update_dictionary(a, b):
    a.update(b)
    return a

def shutdown_process(process):
    i = 0
    while i < 100:
        try:
            os.kill(process.pid, signal.SIGTERM)
        except OSError as e:
            assert e.errno == errno.ESRCH
            return

        if process.status() == psutil.STATUS_ZOMBIE:
            return

        i += 1
        time.sleep(0.1)

    while i < 200:
        try:
            os.kill(process.pid, signal.SIGKILL)
        except OSError as e:
            assert e.errno == errno.ESRCH
            return

        if process.status() == psutil.STATUS_ZOMBIE:
            return

        i += 1
        time.sleep(0.1)
    assert False, "Failed to shutdown process %d (%s)" % (process.pid, process.name())


def shutdown_process_with_children(pid):
    pid = int(pid)
    try:
        process = psutil.Process(pid=pid)
    except psutil.NoSuchProcess:
        return
    children = process.children(recursive=False)
    shutdown_process(process)
    for child in children:
        try:
            shutdown_process(child)
        except:
            pass

def write_to_stdin(process_handle, text):
    lib = BuiltIn().get_library_instance('Process')
    obj = lib.get_process_object()
    obj.stdin.write(text + "\n")
    obj.stdin.flush()
    obj.stdin.close()
    out = obj.stdout.read(4096)
    return out

def get_file_if_exists(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as myfile:
            return myfile.read()
    return None

