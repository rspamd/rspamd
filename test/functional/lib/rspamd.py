import demjson
import grp
import os
import os.path
import psutil
import glob
import pwd
import re
import shutil
import signal
import socket
import errno
import sys
import tempfile
import time
import subprocess
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
    with open(filename, 'rb') as f:
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

# copy-paste from 
# https://hg.python.org/cpython/file/6860263c05b3/Lib/shutil.py#l1068
# As soon as we move to Python 3, this should be removed in favor of shutil.which()
def python3_which(cmd, mode=os.F_OK | os.X_OK, path=None):
    """Given a command, mode, and a PATH string, return the path which
    conforms to the given mode on the PATH, or None if there is no such
    file.

    `mode` defaults to os.F_OK | os.X_OK. `path` defaults to the result
    of os.environ.get("PATH"), or can be overridden with a custom search
    path.
    """

    # Check that a given file can be accessed with the correct mode.
    # Additionally check that `file` is not a directory, as on Windows
    # directories pass the os.access check.
    def _access_check(fn, mode):
        return (os.path.exists(fn) and os.access(fn, mode)
                and not os.path.isdir(fn))

    # If we're given a path with a directory part, look it up directly rather
    # than referring to PATH directories. This includes checking relative to the
    # current directory, e.g. ./script
    if os.path.dirname(cmd):
        if _access_check(cmd, mode):
            return cmd
        return None

    if path is None:
        path = os.environ.get("PATH", os.defpath)
    if not path:
        return None
    path = path.split(os.pathsep)

    if sys.platform == "win32":
        # The current directory takes precedence on Windows.
        if not os.curdir in path:
            path.insert(0, os.curdir)

        # PATHEXT is necessary to check on Windows.
        pathext = os.environ.get("PATHEXT", "").split(os.pathsep)
        # See if the given file matches any of the expected path extensions.
        # This will allow us to short circuit when given "python.exe".
        # If it does match, only test that one, otherwise we have to try
        # others.
        if any(cmd.lower().endswith(ext.lower()) for ext in pathext):
            files = [cmd]
        else:
            files = [cmd + ext for ext in pathext]
    else:
        # On other platforms you don't have things like PATHEXT to tell you
        # what file suffixes are executable, so just pass on cmd as-is.
        files = [cmd]

    seen = set()
    for dir in path:
        normdir = os.path.normcase(dir)
        if not normdir in seen:
            seen.add(normdir)
            for thefile in files:
                name = os.path.join(dir, thefile)
                if _access_check(name, mode):
                    return name
    return None


def collect_lua_coverage():
    if python3_which("luacov-coveralls") is None:
        logger.info("luacov-coveralls not found, will not collect Lua coverage")
        return

    # decided not to do optional coverage so far
    #if not 'ENABLE_LUA_COVERAGE' in os.environ['HOME']:
    #    logger.info("ENABLE_LUA_COVERAGE is not present in env, will not collect Lua coverage")
    #    return

    current_directory = os.getcwd()
    report_file = current_directory + "/lua_coverage_report.json"
    old_report = current_directory + "/lua_coverage_report.json.old"

    tmp_dir = BuiltIn().get_variable_value("${TMPDIR}")
    coverage_files = glob.glob('%s/*.luacov.stats.out' % (tmp_dir))

    for stat_file in coverage_files:
        shutil.move(stat_file, "luacov.stats.out")
        # logger.console("statfile: " + stat_file)

        if (os.path.isfile(report_file)):
            shutil.move(report_file, old_report)
            p = subprocess.Popen(["luacov-coveralls", "-o", report_file, "-j", old_report, "--merge", "--dryrun"], 
                                 stdout = subprocess.PIPE, stderr= subprocess.PIPE)
            output,error = p.communicate()

            logger.info("luacov-coveralls stdout: " + output)
            logger.info("luacov-coveralls stderr: " + error)
            os.remove(old_report)
        else:
            p = subprocess.Popen(["luacov-coveralls", "-o", report_file, "--dryrun"], stdout = subprocess.PIPE, stderr= subprocess.PIPE)
            output,error = p.communicate()

            logger.info("luacov-coveralls stdout: " + output)
            logger.info("luacov-coveralls stderr: " + error)
        os.remove("luacov.stats.out")

