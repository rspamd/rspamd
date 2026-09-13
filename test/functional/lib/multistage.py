"""Wire-level DATA continuation regressions, independent of libmilter."""
import hashlib
import http.client
import http.server
import json
import socket
import struct
import threading
import time

KEY = b'test-only-multistage-shared-key-01'


def _seal(kind, payload, key=KEY):
    body = json.dumps(payload, separators=(',', ':')).encode()
    mac = hashlib.blake2b(b'rspamd-multistage-v1\0' + kind.encode() + b'\0' + body,
                         key=key).hexdigest().encode()
    return mac + b'.' + body


class Milter:
    def __init__(self, host, port, ip='192.0.2.1', helo='mail.example.com'):
        self.sock = socket.create_connection((host, int(port)), timeout=5)
        self.send(b'O', struct.pack('!III', 6, 0x1ff, 0x1fffff))
        command, data = self.read()
        assert command == b'O'
        _, _, protocol = struct.unpack('!III', data)
        assert not protocol & 0x10000, 'NR_DATA must be disabled'
        family = b'6' if ':' in ip else b'4'
        self.send(b'C', b'mail.example.com\0' + family + struct.pack('!H', 25) + ip.encode() + b'\0')
        self.send(b'H', helo.encode() + b'\0')

    def send(self, command, data=b''):
        self.sock.sendall(struct.pack('!I', 1 + len(data)) + command + data)

    def exact(self, size):
        result = b''
        while len(result) < size:
            part = self.sock.recv(size - len(result))
            assert part, 'milter closed before replying'
            result += part
        return result

    def read(self):
        size, = struct.unpack('!I', self.exact(4))
        assert 0 < size < 1024 * 1024
        frame = self.exact(size)
        return frame[:1], frame[1:]

    def envelope(self, sender='continue'):
        self.send(b'M', ('<' + sender + '@example.com>\0').encode())
        self.send(b'R', b'<recipient@example.org>\0')

    def data(self):
        self.send(b'T')
        return self.read()[0]

    def eom(self, expected):
        command, headers = self.finish_message()
        assert command in (b'a', b'c'), command
        assert headers.get('X-Multistage-Test') == expected, headers

    def finish_message(self, headers=None, body=b'A real message body.\r\n'):
        for name, value in (headers or [('From', 'sender@example.com'),
                                       ('To', 'recipient@example.org')]):
            self.send(b'L', name.encode() + b'\0' + value.encode() + b'\0')
        self.send(b'N')
        self.send(b'B', body)
        self.send(b'E')
        added = {}
        for _ in range(32):
            command, data = self.read()
            if command == b'h':
                name, value = data.split(b'\0')[:2]
                added[name.decode()] = value.decode().strip()
            if command in (b'a', b'c', b'r', b't', b'y', b'd'):
                return command, added
        raise AssertionError('no final EOM response')

    def close(self):
        try:
            self.send(b'Q')
        finally:
            self.sock.close()


def multistage_transaction(host, port, scenario):
    client = Milter(host, port)
    try:
        client.envelope(scenario if scenario in ('reject', 'defer', 'async', 'timeout') else 'continue')
        if scenario == 'no_data':
            client.eom('full')
            return
        if scenario == 'abort':
            client.send(b'A')
            client.envelope('async')
            client.send(b'T')
            client.send(b'A')
            client.envelope()
            assert client.data() == b'c'
            client.eom('replayed')
            return
        expected = {'reject': b'r', 'defer': b't'}.get(scenario, b'c')
        assert client.data() == expected
        if expected == b'c':
            client.eom('full' if scenario == 'timeout' else 'replayed')
        else:
            # Postfix sends ABORT before EHLO after a rejected transaction.
            client.send(b'A')
            client.send(b'H', b'new.example.com\0')

        # Reuse the same SMTP connection after both early terminals and EOM.
        client.envelope()
        assert client.data() == b'c'
        client.eom('replayed')
    finally:
        client.close()


def _http(host, port, path, body, headers=None):
    conn = http.client.HTTPConnection(host, int(port), timeout=5)
    try:
        conn.request('POST', path, body, headers or {})
        response = conn.getresponse()
        return response.status, response.read(), response.getheader('Content-Type')
    finally:
        conn.close()


def multistage_fallback(host, proxy_port, stub_port, scanner_port, failure):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            if self.path == '/checkdata':
                if failure == 'disconnect':
                    self.close_connection = True
                    return
                # A syntactically valid signed-looking reject from an untrusted scanner.
                request = json.loads(body[129:])
                result = dict(version=1, issued=time.time(), id=request['id'],
                              binding='wrong', decision='reject')
                body = _seal('data-response', result, b'wrong-key-for-multistage-test-0001')
                code, content_type = 200, 'application/json'
            else:
                code, body, content_type = _http(host, scanner_port, self.path, body,
                                                dict(self.headers))
            self.send_response(code)
            self.send_header('Content-Length', str(len(body)))
            if content_type:
                self.send_header('Content-Type', content_type)
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer((host, int(stub_port)), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = None
    try:
        client = Milter(host, proxy_port)
        client.envelope()
        assert client.data() == b'c'
        client.eom('full')
    finally:
        if client:
            client.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def multistage_authentication(host, port):
    request = dict(version=1, issued=time.time(), id='a' * 32,
                   metadata=dict(ip='192.0.2.1', helo='mail.example.com',
                                 **{'from': '<continue@example.com>', 'rcpt': ['<rcpt@example.org>']}))
    wire = _seal('data-request', request)
    code, body, _ = _http(host, port, '/checkdata', wire)
    assert code == 200, (code, body)
    result = json.loads(body[129:])
    mac = hashlib.blake2b(b'rspamd-multistage-v1\0data-response\0' + body[129:], key=KEY).hexdigest().encode()
    assert body[:129] == mac + b'.'
    assert result['decision'] == 'continue'
    assert 'DATA_PRODUCER' in result['record']['checks']
    for invalid in (wire[:-1] + b'!', _seal('data-response', request),
                    _seal('data-request', dict(request, issued=time.time() - 301))):
        code, _, _ = _http(host, port, '/checkdata', invalid)
        assert code == 403, code


def multistage_accounting(host, port, controller_port, sender):
    def stats():
        conn = http.client.HTTPConnection(host, int(controller_port), timeout=5)
        try:
            conn.request('GET', '/stat')
            response = conn.getresponse()
            assert response.status == 200
            return json.loads(response.read())
        finally:
            conn.close()

    client = Milter(host, port)
    try:
        before = stats()
        client.envelope(sender)
        decision = client.data()
        after_data = stats()
        if sender == 'continue':
            assert decision == b'c'
            assert after_data['scanned'] == before['scanned']
            client.eom('replayed')
        else:
            assert decision == {'reject': b'r', 'defer': b't'}[sender]
            action = {'reject': 'reject', 'defer': 'soft reject'}[sender]
            assert after_data['actions'][action] == before['actions'][action] + 1
        after = stats()
        assert after['scanned'] == before['scanned'] + 1
        assert stats()['scanned'] == after['scanned']
    finally:
        client.close()
