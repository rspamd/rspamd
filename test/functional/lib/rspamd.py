#  Copyright 2024 Vsevolod Stakhov
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from urllib.request import urlopen
import email
import glob
import grp
import http.client
import os
import os.path
import psutil
import pwd
import select
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import random
import re
import sys
import tempfile

from robot.api import logger
from robot.libraries.BuiltIn import BuiltIn
import json


def Check_JSON(j):
    d = json.JSONDecoder(strict=True).decode(j.decode('utf-8'))
    logger.debug('got json %s' % d)
    assert len(d) > 0
    assert 'error' not in d
    return d


def check_json_log(fn):
    line_count = 0
    f = open(fn, 'r', encoding="utf-8")
    for l in f.readlines():
        d = json.JSONDecoder(strict=True).decode(l)
        assert len(d) > 0
        line_count = line_count + 1
    assert line_count > 0


def cleanup_temporary_directory(directory):
    shutil.rmtree(directory)


def _pabot_slice_id():
    """Return this process' pabot queue index, or None under plain robot.

    pabot passes `--variable PABOTQUEUEINDEX:<n>` to every suite slice it
    executes and prints the same index next to the suite name in its own
    log (`[ID:<n>] EXECUTING Cases.001 Merged.100 General`), so the index
    maps a saved directory back to the sub-suite that produced it. pabot
    uses -1 when there is no slice, plain robot defines nothing at all.
    """
    idx = BuiltIn().get_variable_value("${PABOTQUEUEINDEX}")
    if idx is None:
        return None
    idx = str(idx).strip()
    if not idx.lstrip('-').isdigit() or int(idx) < 0:
        return None
    return idx


def _save_file(source_file, destination_file):
    """Copy source_file to destination_file atomically, best effort.

    Several processes can aim at the same destination: pabot slices of a
    split directory suite share the suite-level directory, and the `*.last`
    copies are global to the whole run. Copy into a unique temporary in the
    destination directory and rename it into place so no reader ever sees a
    half-written log, and only warn on failure -- saving diagnostics must
    never turn a green suite red.
    """
    destination_directory = os.path.dirname(destination_file)
    try:
        fd, tmp_file = tempfile.mkstemp(dir=destination_directory, prefix='.saving-')
        os.close(fd)
    except OSError as e:
        logger.warn('cannot create a temporary file in %s: %s' % (destination_directory, e))
        return
    try:
        shutil.copyfile(source_file, tmp_file)
        os.chmod(tmp_file, 0o644)
        os.replace(tmp_file, destination_file)
    except OSError as e:
        logger.warn('cannot save %s as %s: %s' % (source_file, destination_file, e))
        try:
            os.unlink(tmp_file)
        except OSError:
            pass


def save_run_results(directory, filenames):
    current_directory = os.getcwd()
    save_root = "%s/robot-save" % current_directory
    suite_name = BuiltIn().get_variable_value("${SUITE_NAME}")
    test_name = BuiltIn().get_variable_value("${TEST NAME}")
    if os.path.exists(directory):
        onlyfiles = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        logger.debug('%s content before cleanup: %s' % (directory, onlyfiles))
        if test_name is None:
            # This is suite-level tear down. A directory suite whose
            # __init__.robot owns rspamd (001_merged) is split by pabot into
            # one slice per sub-suite, and every slice runs this very
            # teardown with the same ${SUITE_NAME}: without a per-slice
            # directory they race on the mkdir below and then overwrite each
            # other's logs. Leaf (.robot) suites run whole in one process, so
            # they keep the historical flat layout.
            destination_directory = "%s/%s" % (save_root, suite_name)
            slice_id = _pabot_slice_id()
            suite_source = BuiltIn().get_variable_value("${SUITE_SOURCE}")
            if slice_id is not None and suite_source is not None and os.path.isdir(suite_source):
                destination_directory = "%s/pabot-%s" % (destination_directory, slice_id)
        else:
            destination_directory = "%s/%s/%s" % (save_root, suite_name, test_name)
        os.makedirs(destination_directory, exist_ok=True)
        for file in filenames.split(' '):
            source_file = "%s/%s" % (directory, file)
            logger.debug('check if we can save %s' % source_file)
            if os.path.isfile(source_file):
                logger.debug('found %s, save it' % file)
                _save_file(source_file, "%s/%s" % (destination_directory, file))
                _save_file(source_file, "%s/%s.last" % (save_root, file))


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
    c = http.client.HTTPConnection("%s:%s" % (host, port))
    c.request(method, path, data, headers)
    r = c.getresponse()
    t = r.read()
    s = r.status
    c.close()
    return [s, t]


def HTTP_With_Headers(method, host, port, path, data=None, headers={}):
    """HTTP request that returns response headers.
    Returns [status, body, headers_dict]
    """
    c = http.client.HTTPConnection("%s:%s" % (host, port))
    c.request(method, path, data, headers)
    r = c.getresponse()
    t = r.read()
    s = r.status
    h = dict(r.getheaders())
    c.close()
    return [s, t, h]


def HTTP_Status_And_Reason(method, host, port, path, data=None, headers={}):
    """HTTP request that returns [status, reason, body].

    rspamd_proxy reports a refused request in the status line only -- that
    path writes no body at all -- so the reason phrase is the only assertable
    text.
    """
    c = http.client.HTTPConnection("%s:%s" % (host, port))
    c.request(method, path, data, headers)
    r = c.getresponse()
    t = r.read()
    s = r.status
    reason = r.reason
    c.close()
    return [s, reason, t]


def HTTPS(method, host, port, path, data=None, headers={}):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection("%s:%s" % (host, port), context=ctx)
    c.request(method, path, data, headers)
    r = c.getresponse()
    t = r.read()
    s = r.status
    c.close()
    return [s, t]


def HTTPS_With_Headers(method, host, port, path, data=None, headers={}):
    """HTTPS request that returns response headers.
    Returns [status, body, headers_dict]
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection("%s:%s" % (host, port), context=ctx)
    c.request(method, path, data, headers)
    r = c.getresponse()
    t = r.read()
    s = r.status
    h = dict(r.getheaders())
    c.close()
    return [s, t, h]


def generate_ssl_cert(tmpdir):
    """Generate a self-signed EC certificate and key in tmpdir.
    Returns (cert_path, key_path).
    """
    cert_path = os.path.join(tmpdir, "test-cert.pem")
    key_path = os.path.join(tmpdir, "test-key.pem")
    subprocess.check_call([
        "openssl", "req", "-x509", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:prime256v1",
        "-keyout", key_path, "-out", cert_path,
        "-days", "1", "-nodes",
        "-subj", "/CN=rspamd-test",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Make readable by rspamd worker (runs as nobody)
    os.chmod(cert_path, 0o644)
    os.chmod(key_path, 0o644)
    return cert_path, key_path


def hard_link(src, dst):
    os.link(src, dst)


def make_temporary_directory():
    """Creates and returns a unique temporary directory

    Example:
    | ${RSPAMD_TMPDIR} = | Make Temporary Directory |
    """
    dirname = tempfile.mkdtemp()
    os.chmod(dirname, stat.S_IRUSR |
             stat.S_IXUSR |
             stat.S_IWUSR |
             stat.S_IRGRP |
             stat.S_IXGRP |
             stat.S_IROTH |
             stat.S_IXOTH)
    return dirname


def make_temporary_file():
    return tempfile.mktemp()


def path_splitter(path):
    dirname = os.path.dirname(path)
    basename = os.path.basename(path)
    return [dirname, basename]


def rspamc(addr, port, filename):
    mboxgoo = b"From MAILER-DAEMON Fri May 13 19:17:40 2016\r\n"
    goo = open(filename, 'rb').read()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, port))
    s.send(b"CHECK RSPAMC/1.0\r\nContent-length: ")
    s.send(str(len(goo + mboxgoo)).encode('utf-8'))
    s.send(b"\r\n\r\n")
    s.send(mboxgoo)
    s.send(goo)
    data = b""
    while True:
        chunk = s.recv(32768)
        if not chunk:
            break
        data += chunk
    s.close()
    return data.decode('utf-8')


def Scan_File(filename, **headers):
    addr = BuiltIn().get_variable_value("${RSPAMD_LOCAL_ADDR}")
    port = BuiltIn().get_variable_value("${RSPAMD_PORT_NORMAL}")
    headers["Queue-Id"] = BuiltIn().get_variable_value("${TEST_NAME}")
    c = http.client.HTTPConnection("%s:%s" % (addr, port))
    c.request("POST", "/checkv2", open(filename, "rb"), headers)
    r = c.getresponse()
    assert r.status == 200
    d = json.JSONDecoder(strict=True).decode(r.read().decode('utf-8'))
    c.close()
    BuiltIn().set_test_variable("${SCAN_RESULT}", d)
    return


def Scan_File_Expect_Error(filename, expected_status, port=None, **headers):
    """POST /checkv2 and require a specific HTTP status; return the body.

    Scan_File asserts 200, so a request that must be refused needs its own
    entry point. The body is returned so the caller can assert on the
    protocol error text rather than on the status alone.

    Example:
    | ${body} = | Scan File Expect Error | /dev/null | 400 | File=/tmp/x |
    """
    addr = BuiltIn().get_variable_value("${RSPAMD_LOCAL_ADDR}")
    if port is None:
        port = BuiltIn().get_variable_value("${RSPAMD_PORT_NORMAL}")
    headers["Queue-Id"] = BuiltIn().get_variable_value("${TEST_NAME}")
    c = http.client.HTTPConnection("%s:%s" % (addr, port))
    c.request("POST", "/checkv2", open(filename, "rb"), headers)
    r = c.getresponse()
    status = r.status
    body = r.read().decode('utf-8', errors='replace')
    c.close()
    assert status == int(expected_status), \
        "Expected HTTP %s but got %d: %s" % (expected_status, status, body)
    return body


class _UnixHTTPConnection(http.client.HTTPConnection):
    """http.client speaking to an AF_UNIX listener.

    http.client has no unix transport and every other test config binds
    host:port, so this exists only for the file/shm suites: the whole point
    of the hardening is that a unix socket peer keeps the privileged
    File/Path/Shm inputs that a TCP peer is denied, and that cannot be
    exercised over TCP by definition.
    """

    def __init__(self, socket_path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.socket_path)
        self.sock = s


def unix_socket_connect(socket_path):
    """Connect to a unix socket and close it again, raising if it is not there.

    Readiness probe: Rspamd Startup Check only pings a TCP port, so a worker
    that also binds a unix socket needs its own barrier.

    Example:
    | Wait Until Keyword Succeeds | 10x | 0.2s | Unix Socket Connect | /tmp/x.sock |
    """
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(socket_path)
    finally:
        s.close()


def Scan_File_Over_Unix_Socket(socket_path, filename, **headers):
    """Like Scan_File but over a unix socket; sets ${SCAN_RESULT}.

    Example:
    | Scan File Over Unix Socket | ${sock} | /dev/null | File=${msg} |
    """
    headers["Queue-Id"] = BuiltIn().get_variable_value("${TEST_NAME}")
    c = _UnixHTTPConnection(socket_path)
    try:
        c.request("POST", "/checkv2", open(filename, "rb"), headers)
        r = c.getresponse()
        status = r.status
        body = r.read().decode('utf-8', errors='replace')
    finally:
        c.close()
    assert status == 200, "Expected HTTP 200 but got %d: %s" % (status, body)
    d = json.JSONDecoder(strict=True).decode(body)
    BuiltIn().set_test_variable("${SCAN_RESULT}", d)
    return


def _shm_object_dir():
    """Directory backing POSIX shared memory names, or None.

    rspamd resolves an `Shm` value with shm_open() only where cmake found
    POSIX shared memory to be sane, which is Linux (see HAVE_SANE_SHMEM);
    everywhere else the value is an ordinary path handed to open(2). glibc
    maps a shm name onto /dev/shm/<name>, so the object can be created as a
    plain file there without any third party module.
    """
    if sys.platform.startswith('linux'):
        for d in ('/dev/shm', '/run/shm'):
            if os.path.isdir(d):
                return d
    return None


def create_shm_payload(content=None, size=None):
    """Create an object that an `Shm` request header can name.

    Returns [name, path]: `name` goes into the header, `path` is what
    Remove Shm Payload has to unlink. Give either the exact `content` or a
    `size` in bytes of filler text.

    Example:
    | ${name} | ${path} = | Create Shm Payload | size=200000 |
    """
    if content is None:
        nbytes = int(size)
        content = (("X" * 63 + "\n") * (nbytes // 64 + 1))[:nbytes]
    data = content if isinstance(content, bytes) else content.encode('utf-8')
    uniq = "rspamd-fshm-%016x" % random.getrandbits(64)
    shmdir = _shm_object_dir()
    if shmdir:
        path = os.path.join(shmdir, uniq)
        name = "/" + uniq
    else:
        path = os.path.join(tempfile.gettempdir(), uniq)
        name = path
    with open(path, "wb") as f:
        f.write(data)
    # The daemon may run as another user (nobody in CI)
    os.chmod(path, 0o644)
    return [name, path]


def remove_shm_payload(path):
    """Unlink an object made by Create Shm Payload; never fails."""
    try:
        os.unlink(path)
    except OSError:
        pass


def write_readable_file(path, content):
    """Write `content` to `path` and make it world readable; return the path.

    Robot's Create File obeys the umask and the daemon may run as another
    user (nobody in CI), so the mode is set explicitly here.
    """
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, 0o644)
    return path


def write_filler_file(path, size):
    """Write `size` bytes of printable filler to `path` and return the path.

    Used where the content is irrelevant and only the size matters, e.g. for
    the max_message limit on file inputs. Robot's Create File would need the
    whole payload as a variable first.
    """
    nbytes = int(size)
    with open(path, "wb") as f:
        chunk = (b"X" * 63 + b"\n") * 1024
        written = 0
        while written < nbytes:
            piece = chunk[:min(len(chunk), nbytes - written)]
            f.write(piece)
            written += len(piece)
    os.chmod(path, 0o644)
    return path


_PENDING_SOCKETS = []


def open_pending_connections(addr, port, count, path="/checkv2"):
    """Open connections that are accepted but whose body never arrives.

    A complete request head announcing a body is sent and the body is then
    withheld, which is exactly the "accepted and body-pending" state the
    admission limits are meant to count. The sockets are kept in a module
    level list so Close Pending Connections can release them from a teardown
    even after a failure.

    A worker that is already at its limit accepts and closes the connection at
    once, so a socket opened here does not necessarily hold a slot: use Pending
    Connections Alive to tell the two apart.

    Example:
    | Open Pending Connections | 127.0.0.1 | ${port} | 2 |
    """
    head = ("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: 4096\r\n"
            "Connection: close\r\n\r\n" % (path, addr)).encode()
    opened = 0
    for _ in range(int(count)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((addr, int(port)))
        s.sendall(head)
        _PENDING_SOCKETS.append(s)
        opened += 1
    return opened


def pending_connections_alive():
    """How many pending connections the worker has not closed on us.

    A connection that arrives when the worker is already at its limit is
    accepted and closed at once, which the client sees as nothing more than a
    socket that has become readable at EOF -- so opening a connection is not
    proof that it occupies a slot. Call this once a probe connection sent after
    the batch has been answered: the listen queue is FIFO, so by then the worker
    has decided about every socket opened before that probe.
    """
    alive = 0
    for s in _PENDING_SOCKETS:
        readable, _, _ = select.select([s], [], [], 0)
        if not readable:
            alive += 1
    return alive


def close_one_pending_connection():
    """Close a single socket opened by Open Pending Connections.

    Frees exactly one admission slot, which is what the counting tests need:
    the worker must admit again as soon as one client goes away.
    """
    if not _PENDING_SOCKETS:
        raise AssertionError("no pending connection to close")
    _PENDING_SOCKETS.pop().close()
    return len(_PENDING_SOCKETS)


def close_pending_connections():
    """Close every socket opened by Open Pending Connections."""
    closed = 0
    while _PENDING_SOCKETS:
        s = _PENDING_SOCKETS.pop()
        try:
            s.close()
            closed += 1
        except OSError:
            pass
    return closed


def connection_admitted(addr, port, timeout=5):
    """True when addr:port serves a request, False when the limit refuses it.

    Over its admission limit rspamd still accepts the connection -- the
    listen watcher is level triggered, so merely leaving it in the backlog
    would spin the worker -- and closes it at once. From the client side that
    is a successful connect followed by an immediate EOF or reset.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(float(timeout))
    req = ("GET /ping HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
           % addr).encode()
    try:
        s.connect((addr, int(port)))
        s.sendall(req)
        data = s.recv(64)
    except socket.timeout:
        # Admitted but not answered in time: not a refusal, and the caller's
        # own retry loop is the right place to deal with it.
        return True
    except OSError:
        return False
    finally:
        s.close()
    return data != b""


def _build_multipart(boundary, metadata_json, message_bytes):
    """Build a multipart/form-data body with metadata and message parts."""
    body = b""
    body += ("--" + boundary + "\r\n").encode()
    body += b"Content-Disposition: form-data; name=\"metadata\"\r\n"
    body += b"Content-Type: application/json\r\n"
    body += b"\r\n"
    if isinstance(metadata_json, str):
        metadata_json = metadata_json.encode('utf-8')
    body += metadata_json
    body += b"\r\n"
    body += ("--" + boundary + "\r\n").encode()
    body += b"Content-Disposition: form-data; name=\"message\"\r\n"
    body += b"\r\n"
    if isinstance(message_bytes, str):
        message_bytes = message_bytes.encode('utf-8')
    body += message_bytes
    body += b"\r\n"
    body += ("--" + boundary + "--\r\n").encode()
    return body


def _build_multipart_single(boundary, part_name, part_data, content_type=None):
    """Build a multipart/form-data body with a single part."""
    body = b""
    body += ("--" + boundary + "\r\n").encode()
    body += ("Content-Disposition: form-data; name=\"%s\"\r\n" % part_name).encode()
    if content_type:
        body += ("Content-Type: %s\r\n" % content_type).encode()
    body += b"\r\n"
    if isinstance(part_data, str):
        part_data = part_data.encode('utf-8')
    body += part_data
    body += b"\r\n"
    body += ("--" + boundary + "--\r\n").encode()
    return body


def _parse_multipart_response(body, content_type):
    """Parse a multipart/mixed response and return the 'result' part data as string."""
    if isinstance(body, bytes):
        body = body.decode('utf-8', errors='replace')

    # Extract boundary from Content-Type header
    m = re.search(r'boundary="?([^";]+)"?', content_type)
    if not m:
        raise ValueError("No boundary found in Content-Type: %s" % content_type)
    boundary = m.group(1)

    # Split on boundary
    parts = body.split("--" + boundary)
    for part in parts:
        if part.startswith("--"):
            continue  # closing boundary
        if not part.strip():
            continue

        # Split headers from body
        if "\r\n\r\n" in part:
            headers, data = part.split("\r\n\r\n", 1)
        elif "\n\n" in part:
            headers, data = part.split("\n\n", 1)
        else:
            continue

        # Check if this is the "result" part
        if 'name="result"' in headers:
            # Strip trailing \r\n
            data = data.rstrip("\r\n")
            return data

    raise ValueError("No 'result' part found in multipart response")


def Scan_File_V3(filename, metadata=None, **headers):
    """Send a /checkv3 multipart request and set ${SCAN_RESULT}."""
    addr = BuiltIn().get_variable_value("${RSPAMD_LOCAL_ADDR}")
    port = BuiltIn().get_variable_value("${RSPAMD_PORT_NORMAL}")

    meta = metadata if metadata else {}
    meta_json = json.dumps(meta)
    message_data = open(filename, "rb").read()

    boundary = "----rspamd-test-%016x" % random.getrandbits(64)
    body = _build_multipart(boundary, meta_json, message_data)

    headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
    if "Queue-Id" not in headers:
        headers["Queue-Id"] = BuiltIn().get_variable_value("${TEST_NAME}")

    c = http.client.HTTPConnection("%s:%s" % (addr, port))
    c.request("POST", "/checkv3", body, headers)
    r = c.getresponse()
    assert r.status == 200, "Expected HTTP 200 but got %d" % r.status

    resp_body = r.read()
    resp_ct = r.getheader("Content-Type", "")
    result_data = _parse_multipart_response(resp_body, resp_ct)

    d = json.JSONDecoder(strict=True).decode(result_data)
    c.close()
    BuiltIn().set_test_variable("${SCAN_RESULT}", d)
    return


def Scan_File_V3_Expect_Error(filename, expected_status, metadata=None,
                               body_override=None, content_type_override=None,
                               **headers):
    """Send a /checkv3 request and expect a specific HTTP error status."""
    addr = BuiltIn().get_variable_value("${RSPAMD_LOCAL_ADDR}")
    port = BuiltIn().get_variable_value("${RSPAMD_PORT_NORMAL}")

    boundary = "----rspamd-test-%016x" % random.getrandbits(64)

    if body_override is not None:
        body = body_override
    else:
        meta = metadata if metadata else {}
        meta_json = json.dumps(meta)
        message_data = open(filename, "rb").read() if filename else b""
        body = _build_multipart(boundary, meta_json, message_data)

    if content_type_override:
        headers["Content-Type"] = content_type_override
    else:
        headers["Content-Type"] = "multipart/form-data; boundary=" + boundary

    if "Queue-Id" not in headers:
        headers["Queue-Id"] = BuiltIn().get_variable_value("${TEST_NAME}")

    c = http.client.HTTPConnection("%s:%s" % (addr, port))
    c.request("POST", "/checkv3", body, headers)
    r = c.getresponse()
    actual_status = r.status
    r.read()
    c.close()
    assert actual_status == int(expected_status), \
        "Expected HTTP %s but got %d" % (expected_status, actual_status)
    return


def Scan_File_V3_Single_Part(part_name, part_data, content_type_part=None, **headers):
    """Send a /checkv3 request with only a single part."""
    addr = BuiltIn().get_variable_value("${RSPAMD_LOCAL_ADDR}")
    port = BuiltIn().get_variable_value("${RSPAMD_PORT_NORMAL}")

    boundary = "----rspamd-test-%016x" % random.getrandbits(64)
    body = _build_multipart_single(boundary, part_name, part_data, content_type_part)

    headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
    if "Queue-Id" not in headers:
        headers["Queue-Id"] = BuiltIn().get_variable_value("${TEST_NAME}")

    c = http.client.HTTPConnection("%s:%s" % (addr, port))
    c.request("POST", "/checkv3", body, headers)
    r = c.getresponse()
    status = r.status
    r.read()
    c.close()
    return status


def _build_multipart_meta(boundary, meta_bytes, meta_ctype, message_bytes):
    """multipart/form-data body with an explicit metadata Content-Type."""
    if isinstance(message_bytes, str):
        message_bytes = message_bytes.encode('utf-8')
    body = b""
    body += ("--" + boundary + "\r\n").encode()
    body += b'Content-Disposition: form-data; name="metadata"\r\n'
    body += ("Content-Type: %s\r\n\r\n" % meta_ctype).encode()
    body += meta_bytes + b"\r\n"
    body += ("--" + boundary + "\r\n").encode()
    body += b'Content-Disposition: form-data; name="message"\r\n\r\n'
    body += message_bytes + b"\r\n"
    body += ("--" + boundary + "--\r\n").encode()
    return body


def _v3_disposition_name(content_disposition):
    m = re.search(r'name="?([^";]+)"?', content_disposition or "")
    return m.group(1) if m else None


def _v3_parts_form_data(body, content_type):
    """Parse a multipart/form-data reply with a self-contained HTTP multipart
    splitter.

    Deliberately splits on the boundary delimiter itself (the way HTTP
    multipart tooling does), rather than reusing the stdlib MIME/email parser
    used for the message/rfc822 case, to prove the reply is consumable by
    standard HTTP multipart tooling. Kept dependency-free on purpose so the
    test needs no third-party module. Binary part payloads (e.g. zstd) are
    preserved byte-exact: only the single CRLF framing each part is trimmed.
    """
    m = re.search(r'boundary="?([^";]+)"?', content_type or "")
    if not m:
        raise ValueError("no boundary in Content-Type: %r" % content_type)
    delimiter = b"--" + m.group(1).strip().encode()
    parts = []
    for chunk in body.split(delimiter):
        # Closing "--boundary--" terminator and the (empty) preamble.
        if chunk[:2] == b"--" or not chunk:
            continue
        # Trim exactly the CRLF after the boundary line and the CRLF before
        # the next boundary; never strip into binary content.
        if chunk[:2] == b"\r\n":
            chunk = chunk[2:]
        elif chunk[:1] == b"\n":
            chunk = chunk[1:]
        if chunk[-2:] == b"\r\n":
            chunk = chunk[:-2]
        elif chunk[-1:] == b"\n":
            chunk = chunk[:-1]
        head, sep, data = chunk.partition(b"\r\n\r\n")
        if not sep:
            continue
        hdrs = {}
        for line in head.split(b"\r\n"):
            k, _, v = line.partition(b":")
            if _:
                hdrs[k.decode().strip().lower()] = v.decode().strip()
        parts.append({
            "name": _v3_disposition_name(hdrs.get("content-disposition", "")),
            "ctype": hdrs.get("content-type", ""),
            "encoding": hdrs.get("content-encoding", ""),
            "data": data,
        })
    return parts


def _v3_parts_mime(body, content_type):
    """Parse a multipart/mixed reply with the stdlib MIME parser (email)."""
    full = b"Content-Type: " + content_type.encode() + b"\r\n\r\n" + body
    msg = email.message_from_bytes(full)
    parts = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        parts.append({
            "name": part.get_param("name", header="content-disposition"),
            "ctype": part.get_content_type(),
            "encoding": part.get("Content-Encoding", "") or "",
            "data": part.get_payload(decode=True),
        })
    return parts


def _v3_decode_result(part):
    """Decode a 'result' part's payload into a dict per its Content-Type."""
    if not part or part.get("encoding"):
        # Compressed payloads are not decoded here (zstd has no stdlib codec)
        return None
    data = part["data"]
    if "msgpack" in (part["ctype"] or ""):
        import msgpack
        return msgpack.unpackb(data, raw=False)
    return json.loads(data)


def Scan_File_V3_Negotiated(filename, accept=None, accept_encoding=None,
                            port=None, metadata=None, metadata_format="json",
                            **headers):
    """Send /checkv3 with explicit Accept / Accept-Encoding and parse the reply.

    Sets ${SCAN_RESULT} to the parsed scan result (when the reply carries one,
    i.e. not a 406) so the usual Expect Symbol/Action keywords work. Returns a
    dict describing the negotiated reply: status, content_type, vary, parser,
    result_ctype, parts (name -> content-type), part_encodings.
    """
    addr = BuiltIn().get_variable_value("${RSPAMD_LOCAL_ADDR}")
    if port is None:
        port = BuiltIn().get_variable_value("${RSPAMD_PORT_NORMAL}")

    meta = metadata if metadata else {}
    if metadata_format == "msgpack":
        import msgpack
        meta_bytes = msgpack.packb(meta)
        meta_ctype = "application/msgpack"
    else:
        meta_bytes = json.dumps(meta).encode('utf-8')
        meta_ctype = "application/json"

    message_data = open(filename, "rb").read()
    boundary = "----rspamd-test-%016x" % random.getrandbits(64)
    body = _build_multipart_meta(boundary, meta_bytes, meta_ctype, message_data)

    headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
    if accept is not None:
        headers["Accept"] = accept
    if accept_encoding is not None:
        headers["Accept-Encoding"] = accept_encoding
    if "Queue-Id" not in headers:
        headers["Queue-Id"] = BuiltIn().get_variable_value("${TEST_NAME}")

    c = http.client.HTTPConnection("%s:%s" % (addr, port))
    c.request("POST", "/checkv3", body, headers)
    r = c.getresponse()
    resp_body = r.read()
    ct = r.getheader("Content-Type", "") or ""
    vary = r.getheader("Vary", "") or ""
    status = r.status
    c.close()

    info = {
        "status": status,
        "content_type": ct,
        "vary": vary,
        "parser": "none",
        "result_ctype": "",
        "parts": {},
        "part_encodings": [],
    }

    if status != 200:
        return info

    result = None
    if ct.startswith("application/json"):
        info["parser"] = "json"
        info["result_ctype"] = "application/json"
        result = json.loads(resp_body)
    elif ct.startswith("application/msgpack"):
        import msgpack
        info["parser"] = "msgpack"
        info["result_ctype"] = "application/msgpack"
        result = msgpack.unpackb(resp_body, raw=False)
    elif ct.startswith("multipart/mixed"):
        info["parser"] = "mime"
        parts = _v3_parts_mime(resp_body, ct)
        info["parts"] = {p["name"]: p["ctype"] for p in parts}
        info["part_encodings"] = [p["encoding"] for p in parts if p["encoding"]]
        rp = next((p for p in parts if p["name"] == "result"), None)
        info["result_ctype"] = rp["ctype"] if rp else ""
        result = _v3_decode_result(rp)
    elif ct.startswith("multipart/form-data"):
        info["parser"] = "form-data"
        parts = _v3_parts_form_data(resp_body, ct)
        info["parts"] = {p["name"]: p["ctype"] for p in parts}
        info["part_encodings"] = [p["encoding"] for p in parts if p["encoding"]]
        rp = next((p for p in parts if p["name"] == "result"), None)
        info["result_ctype"] = rp["ctype"] if rp else ""
        result = _v3_decode_result(rp)

    if result is not None:
        BuiltIn().set_test_variable("${SCAN_RESULT}", result)

    return info


def Scan_File_SSL(filename, port=None, **headers):
    """Like Scan_File but over HTTPS (TLS) to the normal worker SSL port."""
    addr = BuiltIn().get_variable_value("${RSPAMD_LOCAL_ADDR}")
    if port is None:
        port = BuiltIn().get_variable_value("${RSPAMD_PORT_NORMAL_SSL}")
    headers["Queue-Id"] = BuiltIn().get_variable_value("${TEST_NAME}")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection("%s:%s" % (addr, port), context=ctx)
    c.request("POST", "/checkv2", open(filename, "rb"), headers)
    r = c.getresponse()
    assert r.status == 200, "Expected HTTP 200 but got %d" % r.status
    d = json.JSONDecoder(strict=True).decode(r.read().decode('utf-8'))
    c.close()
    BuiltIn().set_test_variable("${SCAN_RESULT}", d)
    return


def Scan_File_V3_SSL(filename, port=None, metadata=None, **headers):
    """Like Scan_File_V3 but over HTTPS (TLS)."""
    addr = BuiltIn().get_variable_value("${RSPAMD_LOCAL_ADDR}")
    if port is None:
        port = BuiltIn().get_variable_value("${RSPAMD_PORT_NORMAL_SSL}")

    meta = metadata if metadata else {}
    meta_json = json.dumps(meta)
    message_data = open(filename, "rb").read()

    boundary = "----rspamd-test-%016x" % random.getrandbits(64)
    body = _build_multipart(boundary, meta_json, message_data)

    headers["Content-Type"] = "multipart/form-data; boundary=" + boundary
    if "Queue-Id" not in headers:
        headers["Queue-Id"] = BuiltIn().get_variable_value("${TEST_NAME}")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection("%s:%s" % (addr, port), context=ctx)
    c.request("POST", "/checkv3", body, headers)
    r = c.getresponse()
    assert r.status == 200, "Expected HTTP 200 but got %d" % r.status

    resp_body = r.read()
    resp_ct = r.getheader("Content-Type", "")
    result_data = _parse_multipart_response(resp_body, resp_ct)

    d = json.JSONDecoder(strict=True).decode(result_data)
    c.close()
    BuiltIn().set_test_variable("${SCAN_RESULT}", d)
    return


def Send_SIGUSR1(pid):
    pid = int(pid)
    os.kill(pid, signal.SIGUSR1)


def set_directory_ownership(path, username, groupname):
    if os.getuid() == 0:
        uid = pwd.getpwnam(username).pw_uid
        gid = grp.getgrnam(groupname).gr_gid
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
    data = b""
    while True:
        chunk = s.recv(32768)
        if not chunk:
            break
        data += chunk
    s.close()
    return data.decode('utf-8')


def TCP_Connect(addr, port):
    """Attempts to open a TCP connection to specified address:port

    Example:
    | Wait Until Keyword Succeeds | 5s | 10ms | TCP Connect | localhost | 8080 |
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)  # seconds
    s.connect((addr, port))
    s.close()


def port_is_free(addr, port):
    """Assert that nothing is listening on addr:port.

    Used by teardown to confirm a just-terminated rspamd has actually
    released its listening sockets before the next suite on this pabot
    worker reuses the same port range. `Wait For Process` only reaps the
    main rspamd; the listening sockets are shared with forked workers and
    can linger briefly after main exits. rspamd sets SO_REUSEADDR, so this
    is NOT about TIME_WAIT -- a still-LISTENing socket from a not-yet-gone
    worker genuinely fails the next bind() with EADDRINUSE. Connecting and
    succeeding means someone is still listening -> raise so Wait Until
    Keyword Succeeds retries; connection refused means the port is free.

    Example:
    | Wait Until Keyword Succeeds | 10s | 0.2s | Port Is Free | 127.0.0.1 | 25790 |
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect((addr, int(port)))
    except (ConnectionRefusedError, socket.timeout, OSError):
        return True
    finally:
        s.close()
    raise AssertionError("port %s:%s is still in use" % (addr, port))


def try_reap_zombies():
    try:
        os.waitpid(-1, os.WNOHANG)
    except ChildProcessError:
        pass


def ping_rspamd(addr, port):
    return str(urlopen("http://%s:%s/ping" % (addr, port)).read())


def controller_auth_status(addr, port, password):
    """Sends a controller /auth request and returns its HTTP status code.

    Unlike rspamc, this distinguishes a rejected password (401) from a
    throttled source (429).

    Example:
    | ${code} = | Controller Auth Status | ${RSPAMD_LOCAL_ADDR} | ${RSPAMD_PORT_CONTROLLER} | q1 |
    """
    conn = http.client.HTTPConnection(addr, int(port), timeout=10)
    try:
        conn.request("GET", "/auth", headers={"Password": password})
        return conn.getresponse().status
    finally:
        conn.close()


def redis_check(addr, port):
    """Attempts to open a TCP connection to specified address:port

    Example:
    | Wait Until Keyword Succeeds | 5s | 10ms | TCP Connect | localhost | 8080 |
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)  # seconds
    s.connect((addr, port))
    if s.sendall(b"ECHO TEST\n"):
        result = s.recv(128)
        return result == b'TEST\n'
    else:
        return False


def update_dictionary(a, b):
    a.update(b)
    return a


TERM_TIMEOUT = 10  # wait after sending a SIGTERM signal
KILL_WAIT = 20  # additional wait after sending a SIGKILL signal


def shutdown_process(process):
    # send SIGTERM
    process.terminate()

    try:
        process.wait(TERM_TIMEOUT)
        return
    except psutil.TimeoutExpired:
        logger.info("PID {} is not terminated in {} seconds, sending SIGKILL...".format(process.pid, TERM_TIMEOUT))
        try:
            # send SIGKILL
            process.kill()
        except psutil.NoSuchProcess:
            # process exited just before we tried to kill
            return

    try:
        process.wait(KILL_WAIT)
    except psutil.TimeoutExpired:
        raise RuntimeError("Failed to shutdown process {} ({})".format(process.pid, process.name()))


def shutdown_process_with_children(pid):
    pid = int(pid)
    try:
        process = psutil.Process(pid=pid)
    except psutil.NoSuchProcess:
        return
    children = process.children(recursive=True)
    shutdown_process(process)
    for child in children:
        try:
            child.kill()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(children, timeout=KILL_WAIT)


def write_to_stdin(process_handle, text):
    if not isinstance(text, bytes):
        text = bytes(text, 'utf-8')
    lib = BuiltIn().get_library_instance('Process')
    obj = lib.get_process_object()
    obj.stdin.write(text + b"\n")
    obj.stdin.flush()
    obj.stdin.close()
    out = obj.stdout.read(4096)
    return out.decode('utf-8')


def get_file_if_exists(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as myfile:
            return myfile.read()
    return None


def _merge_luacov_stats(statsfile, coverage):
    """
    Reads a coverage stats file written by luacov and merges coverage data to
    'coverage' dict: { src_file: hits_list }

    Format of the file defined in:
    https://github.com/keplerproject/luacov/blob/master/src/luacov/stats.lua
    """
    with open(statsfile, 'r') as fh:
        while True:
            # max_line:filename
            line = fh.readline().rstrip()
            if not line:
                break

            max_line, src_file = line.split(':')
            counts = [int(x) for x in fh.readline().split()]
            assert len(counts) == int(max_line)

            if src_file in coverage:
                # enlarge list if needed: lenght of list in different luacov.stats.out files may differ
                old_len = len(coverage[src_file])
                new_len = len(counts)
                if new_len > old_len:
                    coverage[src_file].extend([0] * (new_len - old_len))
                # sum execution counts for each line
                for l, exe_cnt in enumerate(counts):
                    coverage[src_file][l] += exe_cnt
            else:
                coverage[src_file] = counts


def _dump_luacov_stats(statsfile, coverage):
    """
    Saves data to the luacov stats file. Existing file is overwritted if exists.
    """
    src_files = sorted(coverage)

    with open(statsfile, 'w') as fh:
        for src in src_files:
            stats = " ".join(str(n) for n in coverage[src])
            fh.write("%s:%s\n%s\n" % (len(coverage[src]), src, stats))


# File used by luacov to collect coverage stats
LUA_STATSFILE = "luacov.stats.out"


def collect_lua_coverage():
    """
    Merges ${RSPAMD_TMPDIR}/*.luacov.stats.out into luacov.stats.out

    Example:
    | Collect Lua Coverage |
    """
    # decided not to do optional coverage so far
    # if not 'ENABLE_LUA_COVERAGE' in os.environ['HOME']:
    #    logger.info("ENABLE_LUA_COVERAGE is not present in env, will not collect Lua coverage")
    #    return

    tmp_dir = BuiltIn().get_variable_value("${RSPAMD_TMPDIR}")

    coverage = {}
    input_files = []

    for f in glob.iglob("%s/*.luacov.stats.out" % tmp_dir):
        _merge_luacov_stats(f, coverage)
        input_files.append(f)

    if input_files:
        if os.path.isfile(LUA_STATSFILE):
            _merge_luacov_stats(LUA_STATSFILE, coverage)
        _dump_luacov_stats(LUA_STATSFILE, coverage)
        logger.info("%s merged into %s" % (", ".join(input_files), LUA_STATSFILE))
    else:
        logger.info("no *.luacov.stats.out files found in %s" % tmp_dir)


def file_exists(file):
    return os.path.isfile(file)


def redis_stream_read_msgpack(host, port, stream_key):
    """Read latest entry from Redis stream and decode msgpack data.

    Returns decoded dict with metadata fields.

    Example:
    | ${data} = | Redis Stream Read Msgpack | ${RSPAMD_REDIS_ADDR} | ${RSPAMD_REDIS_PORT} | test:structured |
    """
    try:
        import redis
    except ImportError:
        raise Exception("redis module not installed - run: pip install redis")

    try:
        import msgpack
    except ImportError:
        raise Exception("msgpack module not installed - run: pip install msgpack")

    r = redis.Redis(host=host, port=int(port), decode_responses=False)

    # Read from stream
    entries = r.xrange(stream_key, count=1)
    if not entries:
        raise Exception(f"No data in stream {stream_key}")

    # Get the first entry's data field
    entry_id, fields = entries[0]
    if b'data' not in fields:
        raise Exception(f"No data field in stream entry, keys: {list(fields.keys())}")

    msgpack_data = fields[b'data']

    # Decode msgpack with raw=True to preserve bytes, then convert what we can
    decoded = msgpack.unpackb(msgpack_data, raw=True)

    # Convert bytes keys to strings for easier access
    def convert_keys(obj):
        if isinstance(obj, dict):
            return {k.decode('utf-8') if isinstance(k, bytes) else k: convert_keys(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_keys(item) for item in obj]
        elif isinstance(obj, bytes):
            # Try to decode as UTF-8, otherwise keep as bytes
            try:
                return obj.decode('utf-8')
            except UnicodeDecodeError:
                return obj
        return obj

    return convert_keys(decoded)


def validate_structured_metadata(data, expected_fields=None):
    """Validate structured metadata export format.

    Checks that required fields exist and UUID v7 has correct format.

    Example:
    | Validate Structured Metadata | ${data} | uuid,ip,score,action |
    """
    import re

    if expected_fields is None:
        expected_fields = 'uuid,ip,score,action'

    errors = []

    for field in expected_fields.split(','):
        field = field.strip()
        if field not in data:
            errors.append(f"Missing field: {field}")

    # Validate UUID v7 format if present
    if 'uuid' in data:
        uuid = data['uuid']
        # UUID v7: xxxxxxxx-xxxx-7xxx-xxxx-xxxxxxxxxxxx
        if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', str(uuid)):
            errors.append(f"Invalid UUID v7 format: {uuid}")

    if errors:
        raise Exception("Validation errors: " + "; ".join(errors))

    return True


def validate_zstd_compressed_fields(data):
    """Validate that zstd compression markers are set correctly.

    Returns count of compressed fields found.

    Example:
    | ${count} = | Validate Zstd Compressed Fields | ${data} |
    """
    count = 0

    # Check text_compressed flag
    if data.get('text_compressed'):
        count += 1

    # Check attachments
    for att in data.get('attachments', []):
        if att.get('content_compressed'):
            count += 1

    # Check images
    for img in data.get('images', []):
        if img.get('content_compressed'):
            count += 1

    return count


def validate_attachments_have_content_type(data):
    """Validate that attachments have content_type field.

    Returns count of attachments with content_type.

    Example:
    | ${count} = | Validate Attachments Have Content Type | ${data} |
    """
    count = 0
    for att in data.get('attachments', []):
        if 'content_type' in att and att['content_type']:
            count += 1
    return count
