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
from pathlib import Path
import signal
import socket
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
        'inbound': {'stages': ['data'], 'properties': PROPERTIES}, 'outbound': None})
    assert status == 201, (status, r)
    assert r['negotiated']['inbound']['properties'] == PROPERTIES, r
    return r


def payload(mode='accept'):
    raw = f'From: sender@example.com\r\nTo: rcpt@example.com\r\nSubject: test\r\nX-Hooks-Test: {mode}\r\n\r\nhello\r\n'
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
    status, response = invoke(p, r, payload('remove'))
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rspamd', required=True)
    ap.add_argument('--redis', default='redis-server')
    args = ap.parse_args()
    work = Path(tempfile.mkdtemp(prefix='rspamd-mta-hooks-test-'))
    print(f'Logs: {work}', flush=True)
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
options {{ filters = []; url_tld = "{ROOT}/test/lua/unit/test_tld.dat";
  lua_path = "{ROOT}/lualib/?.lua"; task_timeout = 10s;
  hs_cache_dir = "{cache}"; maps_cache_dir = "{cache}"; temp_dir = "{work}"; }}
logging {{ type = "console"; level = "info"; }}
actions {{ reject = 100; discard {{ flags = ["no_threshold"]; }}
  quarantine {{ flags = ["no_threshold"]; }} }}
lua = "{ROOT}/test/functional/lua/mta_hooks.lua";
{worker}
''')
        process = launch(name, [args.rspamd, '-f', '-c', str(cfg), '--var', f'DBDIR={cache}'])
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
        key = namespace + hashlib.sha256(b':add-only-v1:').hexdigest() + ':registration:' + r['registrationId']
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
