#!/usr/bin/env python3
"""Isolated draft-01 integration test: real Redis, four proxy workers, self/upstream.

Run with --rspamd /path/to/rspamd; use RSPAMD_INSTALLROOT for a staged install.
Only subprocesses and temporary files created by this test are modified.
"""
import argparse
import base64
import concurrent.futures
import copy
import hashlib
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import smtplib
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time
import threading
import uuid

TOKEN = 'mta-hooks-test-only-credential-0123456789'
PROPERTIES = ['/stage', '/action', '/timestamp', '/protocol', '/rawMessage',
              '/envelope', '/queue', '/client']
ROOT = Path(__file__).resolve().parents[3]


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_port(p, process):
    until = time.monotonic() + 20
    while time.monotonic() < until:
        if process.poll() is not None:
            raise AssertionError(f'process exited {process.returncode}')
        try:
            with socket.create_connection(('127.0.0.1', p), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError(f'port {p} not ready')


def http(p, path, body=None, method='POST', headers=None):
    conn = HTTPConnection('127.0.0.1', p, timeout=25)
    h = {'Authorization': f'Bearer {TOKEN}', 'Content-Type': 'application/json'}
    h.update(headers or {})
    data = json.dumps(body).encode() if body is not None else None
    try:
        conn.request(method, path, data, h)
        res = conn.getresponse()
        raw = res.read()
        return res.status, json.loads(raw) if raw else None
    finally:
        conn.close()


def registration(p, timeout=20000):
    status, r = http(p, '/v1/hooks/register', {
        'name': 'interop-test', 'serialization': 'json', 'timeoutMs': timeout,
        'inbound': {'stages': ['data'], 'properties': PROPERTIES + ['/tls', '/auth', '/server']}, 'outbound': None})
    assert status == 201, (status, r)
    assert r['negotiated']['inbound']['properties'] == PROPERTIES, r
    return r


def payload(mode='accept'):
    raw = f'From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: test\r\nX-Old: one\r\nX-Old: two\r\nX-Hooks-Test: {mode}\r\n\r\nhello\r\n'
    return {'stage': 'data', 'action': 'accept', 'timestamp': '2026-09-05T12:00:00Z',
            'protocol': {'version': '1.0'}, 'rawMessage': base64.b64encode(raw.encode()).decode(),
            'envelope': {'from': {'address': None, 'parameters': {'SIZE': str(len(raw))}},
                         'to': [{'address': 'rcpt@example.com', 'parameters': {}}]},
            'client': {'ip': '192.0.2.42', 'port': 34567, 'ehlo': 'mx.example.com'},
            'queue': {'id': 'TESTQ'}}


def invoke(p, r, data=None, request_id=None, extra=None):
    headers = {'X-MTA-Hooks-Registration': r['registrationId'],
               'X-MTA-Hooks-Request-Id': request_id or str(uuid.uuid4())}
    headers.update(extra or {})
    return http(p, r['hookEndpoint'], data or payload(), headers=headers)


def check(p):
    for properties in [PROPERTIES[:-1], PROPERTIES + ['/client'], PROPERTIES + [42]]:
        assert http(p, '/v1/hooks/register', {
            'name': 'invalid-properties', 'serialization': 'json',
            'inbound': {'stages': ['data'], 'properties': properties}})[0] == 400
    r = registration(p)
    assert http(p, '/.well-known/mta-hooks', method='GET')[0] == 200
    assert http(p, '/checkv2', payload())[0] == 404
    assert http(p, r['hookEndpoint'], payload(), headers={'Authorization': 'Bearer wrong'})[0] == 401
    status, _ = http(p, r['endpoints']['status'], method='GET')
    assert status == 200
    assert invoke(p, r)[0] == 204
    for mode in ['reject', 'soft reject', 'discard', 'quarantine']:
        status, response = invoke(p, r, payload(mode))
        assert status == 200, (mode, status, response)
        edits = {x['path']: x['value'] for x in response['set']}
        assert edits['/action'] == ('reject' if mode == 'soft reject' else mode)
        if 'reject' in mode:
            assert edits['/response']['code'] == (451 if mode == 'soft reject' else 550)
    status, response = invoke(p, r, payload('headers'), extra={
        'Settings': '{actions {reject = -100}}', 'File': '/not/to/be/opened', 'IP': '127.0.0.1'})
    assert status == 200, (status, response)
    meta = json.loads(response['add'][0]['value']['value'])
    assert meta['ip'] == '192.0.2.42' and meta['from'] == '' and meta['rcpt'] == 'rcpt@example.com', meta
    assert meta['helo'] == 'mx.example.com' and meta['queue'] == 'TESTQ', meta
    assert not meta.get('privileged'), meta
    assert meta['mail_args']['SIZE'], meta
    missing = payload('headers'); missing['client'] = None
    status, response = invoke(p, r, missing)
    assert status == 200, (status, response)
    assert json.loads(response['add'][0]['value']['value'])['ip'] == 'none', response
    status, response = invoke(p, r, payload('invalid'))
    assert status == 503 and 'add' not in response, response
    bad = payload(); bad['rawMessage'] = '!!!!'
    assert invoke(p, r, bad)[0] == 400
    bad = payload(); bad['client']['ehlo'] = 'mx\r\nSettings: evil'
    assert invoke(p, r, bad)[0] == 400
    uid = str(uuid.uuid4()); original = payload('headers')
    first = invoke(p, r, original, uid)
    assert first[0] == 200, first
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        replies = list(pool.map(lambda _: invoke(p, r, original, uid), range(16)))
    assert all(reply == first for reply in replies), replies
    # Race initial requests too: one scan wins; other requests replay or wait.
    racing_id = str(uuid.uuid4())
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        racing = list(pool.map(lambda _: invoke(p, r, original, racing_id), range(16)))
    completed = [reply for reply in racing if reply[0] == 200]
    assert completed and all(reply == completed[0] for reply in completed), racing
    assert all(reply[0] in (200, 503) for reply in racing), racing
    assert invoke(p, r, payload('reject'), uid)[0] == 409
    renewed = registration(p)
    assert invoke(p, renewed, original, uid) == first
    assert http(p, r['endpoints']['deregistration'], method='DELETE')[0] == 200
    assert invoke(p, r)[0] == 410
    assert invoke(p, renewed)[0] == 204
    unknown = copy.deepcopy(r); unknown['registrationId'] = str(uuid.uuid4())
    unknown['hookEndpoint'] = '/v1/hooks/invoke/' + unknown['registrationId']
    assert invoke(p, unknown)[0] == 404
    return renewed


def check_milter(p):
    def send(sock, command, data=b''):
        sock.sendall(struct.pack('!I', len(data) + 1) + command + data)

    def receive(sock):
        def exact(n):
            data = b''
            while len(data) < n:
                chunk = sock.recv(n - len(data))
                assert chunk, 'bridge closed connection'
                data += chunk
            return data
        return exact(struct.unpack('!I', exact(4))[0])

    for mode, verdict in [('accept', b'c'), ('headers', b'c'), ('reject', b'y'),
                          ('soft reject', b'y'), ('discard', b'd'),
                          ('quarantine', b'c'), ('remove', b'c'), ('invalid', b't'),
                          ('subject', b'c'), ('spam', b'c'), ('body', b'c'),
                          ('empty-body', b'c'), ('large-body', b'c'), ('dkim', b'c'), ('body-dkim', b'c')]:
        with socket.create_connection(('127.0.0.1', p), timeout=25) as sock:
            send(sock, b'O', struct.pack('!III', 6, 0x1ff, 0))
            assert receive(sock)[:1] == b'O'
            for command, data in [(b'C', b'mx.example.com\0' + b'4' + struct.pack('!H', 34567) + b'192.0.2.42\0'),
                                  (b'H', b'mx.example.com\0'), (b'M', b'<>\0SIZE=100\0'),
                                  (b'R', b'<rcpt@example.com>\0'), (b'T', b''),
                                  (b'L', b'Subject\0test\0'),
                                  (b'L', b'From\0sender@example.com\0'),
                                  (b'L', b'To\0rcpt@example.com\0'),
                                  (b'L', b'X-Old\0one\0'), (b'L', b'X-Old\0two\0'),
                                  (b'L', b'X-Hooks-Test\0' + mode.encode() + b'\0'),
                                  (b'N', b''), (b'B', b'hello\r\n')]:
                send(sock, command, data)
                assert receive(sock) == b'c', (mode, command)
            send(sock, b'D', b'Ei\0TESTQ\0')
            send(sock, b'E')
            edits = []
            while True:
                frame = receive(sock)
                if frame[:1] in [b'c', b'a', b'r', b't', b'd', b'y']:
                    assert frame[:1] == verdict, (mode, frame)
                    if mode in ['reject', 'soft reject']:
                        assert frame[1:4] == (b'550' if mode == 'reject' else b'451'), frame
                    break
                edits.append(frame)
            if mode == 'headers':
                header = next(x for x in edits if x.startswith(b'hX-Hooks-Metadata\0'))
                metadata = json.loads(header.split(b'\0')[1])
                assert metadata['ip'] == '192.0.2.42' and metadata['queue'] == 'TESTQ', metadata
                assert metadata['from'] == '' and metadata['rcpt'] == 'rcpt@example.com', metadata
            elif mode == 'quarantine':
                assert any(x[:1] == b'q' for x in edits), edits
            elif mode == 'invalid':
                assert not edits, edits
            elif mode == 'subject':
                assert any(b'Subject\0[SPAM] test\0' in x for x in edits), edits
            elif mode == 'spam':
                assert any(b'X-Spam\0Yes\0' in x for x in edits), edits
            elif mode == 'remove':
                removals = [x for x in edits if x[:1] == b'm']
                assert [struct.unpack('!I', x[1:5])[0] for x in removals] == [2, 1], removals
                assert any(b'X-Good\0yes\0' in x for x in edits), edits
            elif mode in ['body', 'empty-body', 'large-body', 'body-dkim']:
                assert any(x[:1] == b'b' for x in edits), (mode, 'missing explicit body replacement')
                replacement = b''.join(x[1:] for x in edits if x[:1] == b'b')
                expected = b'' if mode == 'empty-body' else b'x' * 1500000 + b'\r\n' if mode == 'large-body' else b'replacement\r\n'
                assert replacement == expected, (mode, len(replacement))
                assert any(b'X-Rewritten\0' in x for x in edits), edits
            if mode in ['dkim', 'body-dkim']:
                assert sum(b'DKIM-Signature\0' in x for x in edits) == 2, edits
            send(sock, b'Q')


def check_postfix(mp):
    import dkim
    from email.parser import BytesParser
    if not Path('/.dockerenv').exists():
        raise RuntimeError('--postfix is restricted to the disposable test container')
    for setting in ['myhostname=postfix.interop.test', 'mydestination=localhost',
                    'inet_interfaces=127.0.0.1', 'inet_protocols=ipv4', 'local_recipient_maps=',
                    'mynetworks=127.0.0.0/8', 'smtpd_relay_restrictions=permit_mynetworks,reject',
                    f'smtpd_milters=inet:127.0.0.1:{mp}', 'milter_protocol=6',
                    'milter_default_action=tempfail', 'milter_content_timeout=25s',
                    'defer_transports=smtp,local,relay']:
        subprocess.run(['postconf', '-e', setting], check=True)
    subprocess.run(['postconf', '-M', '2525/inet=2525 inet n - n - - smtpd'], check=True)
    subprocess.run(['postfix', 'start'], check=True)
    public = subprocess.check_output(['openssl', 'rsa', '-in', os.environ['RSPAMD_HOOKS_TEST_KEY'],
                                      '-pubout', '-outform', 'DER'], stderr=subprocess.DEVNULL)
    dns = b'v=DKIM1; k=rsa; p=' + base64.b64encode(public)
    try:
        for mode in ['accept', 'remove', 'presigned', 'subject', 'spam', 'body', 'empty-body', 'large-body',
                     'dkim', 'body-dkim', 'reject', 'soft reject', 'invalid', 'discard', 'quarantine']:
            with smtplib.SMTP('127.0.0.1', 2525, timeout=30) as smtp:
                smtp.ehlo('client.example.com')
                assert smtp.mail('sender@example.com')[0] == 250
                assert smtp.rcpt('rcpt@localhost')[0] == 250
                raw = base64.b64decode(payload('remove' if mode == 'presigned' else mode)['rawMessage'])
                if mode == 'presigned':
                    raw = dkim.sign(raw, b'input', b'example.com', Path(os.environ['RSPAMD_HOOKS_TEST_KEY']).read_bytes(),
                                    canonicalize=(b'simple', b'simple'), include_headers=[b'from', b'to', b'subject', b'x-hooks-test']) + raw
                code, response = smtp.data(raw)
                expected = 550 if mode == 'reject' else 451 if mode in ['soft reject', 'invalid'] else 250
                assert code == expected, (mode, code, response)
                if code != 250 or mode == 'discard':
                    print('PASS Postfix SMTP', mode, code, flush=True)
                    continue
                queue = re.search(rb'queued as ([A-Za-z0-9]+)', response)
                assert queue, response
                queued = subprocess.check_output(['postcat', '-qbh', queue[1].decode()])
                # postcat emits diagnostic delimiters around the RFC 5322 content.
                lines = queued.splitlines(keepends=True)
                start = next((i for i, line in enumerate(lines) if line.startswith(b'*** MESSAGE CONTENTS')), -1) + 1
                end = next((i for i in range(start, len(lines)) if lines[i].startswith(b'*** ')), len(lines))
                message = b''.join(lines[start:end]).replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
                parsed = BytesParser().parsebytes(message)
                if mode in ['remove', 'presigned']:
                    assert parsed.get_all('X-Old') is None and parsed['X-Good'] == 'yes', message
                elif mode == 'subject': assert parsed['Subject'] == '[SPAM] test', message
                elif mode == 'spam': assert parsed['X-Spam'] == 'Yes', message
                if mode in ['body', 'empty-body', 'large-body', 'body-dkim']:
                    actual = message.split(b'\r\n\r\n', 1)[1]
                    expected_body = b'' if mode == 'empty-body' else b'x' * 1500000 + b'\r\n' if mode == 'large-body' else b'replacement\r\n'
                    assert actual == expected_body, (mode, len(actual), len(expected_body))
                    assert parsed['X-Rewritten'] == 'yes'
                if mode in ['dkim', 'body-dkim']:
                    verifier = dkim.DKIM(message)
                    assert len(parsed.get_all('DKIM-Signature')) == 2
                    for index in range(2): assert verifier.verify(idx=index, dnsfunc=lambda *a, **kw: dns), mode
                    assert not dkim.verify(message + b'tampered\r\n', dnsfunc=lambda *a, **kw: dns)
                    assert not dkim.verify(message.replace(b'Subject: test', b'Subject: changed'), dnsfunc=lambda *a, **kw: dns)
                if mode == 'presigned':
                    assert dkim.verify(message, dnsfunc=lambda *a, **kw: dns), 'simple signature was damaged by header edits'
                if mode == 'quarantine':
                    assert list(Path('/var/spool/postfix/hold').rglob(queue[1].decode())), 'message was not held'
                subprocess.run(['postsuper', '-d', queue[1].decode()], check=True, capture_output=True)
            print('PASS Postfix queue', mode, flush=True)
    finally:
        subprocess.run(['postfix', 'stop'], check=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rspamd', required=True)
    ap.add_argument('--redis', default='redis-server')
    ap.add_argument('--milter', help='Path to the real mta-hooks-milter executable')
    ap.add_argument('--postfix', action='store_true', help='Verify synthetic Postfix queues inside Docker')
    args = ap.parse_args()
    if args.postfix and not args.milter:
        ap.error('--postfix requires --milter')
    work = Path(tempfile.mkdtemp(prefix='rspamd-mta-hooks-test-'))
    print(f'Logs: {work}', flush=True)
    os.environ['RSPAMD_HOOKS_TEST_KEY'] = str(ROOT / 'test/functional/configs/dkim.key')
    processes = []
    logs = []
    class SlowHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(3)
            try:
                self.send_response(204)
                self.end_headers()
            except OSError:
                pass

        def log_message(self, *_args):
            pass

    slow = ThreadingHTTPServer(('127.0.0.1', 0), SlowHandler)
    threading.Thread(target=slow.serve_forever, daemon=True).start()

    def launch(name, command):
        log = open(work / f'{name}.log', 'wb')
        logs.append(log)
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(process)
        return process

    def scanner(name, p, backend=None, hooks=False):
        cfg = work / f'{name}.conf'
        cache = work / f'{name}-cache'
        cache.mkdir()
        hooks_config = f'''mta_hooks {{ enabled = true; token = "{TOKEN}";
          redis_host = "127.0.0.1"; redis_port = {rp}; prefix = "{namespace}";
          insecure_loopback = true; }}''' if hooks else ''
        upstream = f'hosts = "127.0.0.1:{backend}";' if backend else 'self_scan = true;'
        worker = f'''worker "rspamd_proxy" {{ bind_socket = "127.0.0.1:{p}"; count = 4;
          milter = false; allow_file_and_shm_inputs = false; {hooks_config}
          upstream {{ name = "local"; default = true; {upstream} }} }}''' if hooks else f'''
          worker "normal" {{ bind_socket = "127.0.0.1:{p}"; count = 2; }}'''
        cfg.write_text(f'''
options {{ filters = ["dkim"]; url_tld = "{ROOT}/test/lua/unit/test_tld.dat";
  lua_path = "{ROOT}/lualib/?.lua"; task_timeout = 10s;
  hs_cache_dir = "{cache}"; maps_cache_dir = "{cache}"; temp_dir = "{work}"; }}
logging {{ type = "console"; level = "info"; }}
actions {{ reject = 100; subject = "[SPAM] %s"; discard {{ flags = ["no_threshold"]; }}
  quarantine {{ flags = ["no_threshold"]; }} }}
lua = "{ROOT}/test/functional/lua/mta_hooks.lua";
{worker}
''')
        command = [args.rspamd, '-f', '-c', str(cfg), '--var', f'DBDIR={cache}']
        if os.geteuid() == 0 and Path('/.dockerenv').exists():
            command.append('--insecure')  # Disposable container, no host mounts or network.
        process = launch(name, command)
        wait_port(p, process)
        return process

    try:
        rp, normal, self_port, upstream_port = port(), port(), port(), port()
        namespace = 'mta-hooks-test:' + uuid.uuid4().hex + ':'
        redis = launch('redis', [args.redis, '--bind', '127.0.0.1', '--port', str(rp),
                                '--save', '', '--appendonly', 'no', '--dir', str(work)])
        wait_port(rp, redis)
        scanner('backend', normal)
        scanner('self', self_port, hooks=True)
        scanner('upstream', upstream_port, backend=normal, hooks=True)
        check(self_port)
        print('PASS self-scan (four workers)', flush=True)
        r = check(upstream_port)
        print('PASS upstream scan (four proxy workers, two backend workers)', flush=True)
        if args.milter:
            for frontend in [self_port, upstream_port]:
                mp, hp = port(), port()
                bridge = launch(f'bridge-{frontend}', [args.milter,
                    '--milter-listen', f'127.0.0.1:{mp}', '--http-listen', f'127.0.0.1:{hp}',
                    '--scanner', f'http://127.0.0.1:{frontend}/v1/hooks/register',
                    '--scanner-token', TOKEN, '--insecure-loopback', '--scanner-no-proxy',
                    '--no-request-macros'])
                wait_port(mp, bridge)
                check_milter(mp)
                if args.postfix:
                    check_postfix(mp)
                bridge.terminate()
                bridge.wait(timeout=10)
            print('PASS real mta-hooks-milter to self/upstream frontends', flush=True)
        # A registration created on one frontend is usable on another instance.
        assert invoke(self_port, r)[0] == 204
        for p in [self_port, upstream_port]:
            short = registration(p, timeout=1000)
            data = payload('slow')
            raw = base64.b64decode(data['rawMessage']).replace(b'\r\n\r\n',
                f'\r\nX-Hooks-Slow-Port: {slow.server_port}\r\n\r\n'.encode(), 1)
            data['rawMessage'] = base64.b64encode(raw).decode()
            started = time.monotonic()
            status, result = invoke(p, short, data)
            assert status == 503, (status, result)
            assert time.monotonic() - started < 1.8, 'deadline extended into postfilters'
            assert invoke(p, r)[0] == 204, 'worker did not recover after timeout'
        print('PASS self/upstream hard deadlines and recovery', flush=True)
        # Expire only a registration owned by this isolated test Redis instance.
        key = namespace + hashlib.sha256(b':data-edits-v2:X-Spam').hexdigest() + ':registration:' + r['registrationId']
        subprocess.run(['redis-cli', '-p', str(rp), 'EXPIRE', key, '0'], check=True, capture_output=True)
        assert invoke(self_port, r)[0] == 404
        r = registration(self_port)
        redis.terminate(); redis.wait(timeout=5)
        assert invoke(upstream_port, r)[0] == 503
        print('PASS cross-instance registration and Redis outage fail-closed', flush=True)
    finally:
        slow.shutdown()
        slow.server_close()
        for process in reversed(processes):
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        for log in logs:
            log.close()
    for name in ['self', 'upstream', 'backend']:
        text = (work / f'{name}.log').read_text(errors='replace')
        assert 'ERROR: AddressSanitizer' not in text, f'sanitizer failure in {name}'
    print('PASS all draft-01 integration checks', flush=True)


if __name__ == '__main__':
    main()
