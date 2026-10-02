"""Cross-worker replay, restart/reload, observer failure and accepted-load checks."""
import concurrent.futures
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time

from test import WORK, wait_port

sys.path.insert(0, '/source/test/functional/lib')
from multistage import Milter


class Router(http.server.ThreadingHTTPServer):
    # The fixture must accept the whole concurrent batch without a TCP
    # retransmission delay from Python's default five-connection backlog.
    request_queue_size = 128
    daemon_threads = True


class Route(http.server.BaseHTTPRequestHandler):
    disable_nagle_algorithm = True

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        port = 11333 if self.path == '/checkdata' else 11334
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ('host', 'connection')}
            conn.request('POST', self.path, body, headers)
            response = conn.getresponse()
            body = response.read()
            self.send_response(response.status)
            self.send_header('Content-Type', response.getheader('Content-Type', 'application/json'))
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        finally:
            conn.close()


def stats():
    conn = http.client.HTTPConnection('127.0.0.1', 11335, timeout=5)
    try:
        conn.request('GET', '/stat')
        response = conn.getresponse()
        assert response.status == 200
        return json.loads(response.read())['multistage']
    finally:
        conn.close()


def envelope(label, helo='mail.example.test'):
    client = Milter('127.0.0.1', 11336, ip='127.0.0.1', helo=helo)
    client.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    client.send(b'M', f'<{label}@pass.example.test>\0'.encode())
    client.send(b'R', b'<bob@localhost>\0')
    return client


def finish(client):
    result, headers = client.finish_message()
    assert result in (b'a', b'c'), result
    state = json.loads(headers['X-Multistage-Integration'])
    assert 'INTEGRATION_BODY' in state['symbols']
    assert 'R_SPF_ALLOW' in state['symbols']
    return state


def transaction(label, data=True, between=None):
    started = time.monotonic()
    client = envelope(label)
    try:
        if data:
            assert client.data() == b'c'
        if between:
            between()
        state = finish(client)
        assert state['spf_calls'] == (0 if data else 1), state
        if data:
            assert state['data_pid'] != state['pid'], state
        return state, time.monotonic() - started
    finally:
        client.close()


def usage(parent):
    """Linux worker CPU and RSS snapshots, without external monitoring tools."""
    cpu = rss = 0
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            fields = path.read_text().rpartition(')')[2].split()
            if int(fields[1]) == parent or int(path.parent.name) == parent:
                cpu += int(fields[11]) + int(fields[12])
                rss += int(fields[21])
        except (FileNotFoundError, ProcessLookupError):
            pass
    return cpu / os.sysconf('SC_CLK_TCK'), rss * os.sysconf('SC_PAGE_SIZE')


def benchmark(process, data):
    count = 120
    concurrency = 8
    cpu_before, _ = usage(process.pid)
    before = stats()
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(lambda n: transaction(f'load-{data}-{n}', data), range(count)))
    elapsed = time.monotonic() - started
    cpu_after, rss = usage(process.pid)
    latencies = sorted(seconds for _, seconds in results)
    after = stats()
    assert after['record_imported'] - before['record_imported'] == (count if data else 0)
    assert after['data_fallback'] == before['data_fallback']
    result = {
        'mode': 'DATA+EOM' if data else 'EOM-only', 'messages': count,
        'concurrency': concurrency, 'messages_per_second': count / elapsed,
        'p50_ms': latencies[count // 2] * 1000, 'p95_ms': latencies[int(count * .95)] * 1000,
        'cpu_seconds': cpu_after - cpu_before, 'rss_bytes': rss,
        'eom_spf_calls': sum(state['spf_calls'] for state, _ in results),
        'eom_dns_requests': sum(state['dns'] for state, _ in results),
    }
    print('BENCHMARK', json.dumps(result, sort_keys=True), flush=True)


def main():
    if not Path('/.dockerenv').exists():
        raise RuntimeError('Run only inside the disposable integration image')
    WORK.mkdir()
    config = WORK / 'failure.conf'
    config.write_text('''
.include "/opt/postfix-data/settings.conf"
worker { type = "normal"; bind_socket = "127.0.0.1:11333"; count = 1; }
worker { type = "normal"; bind_socket = "127.0.0.1:11334"; count = 1; }
worker { type = "controller"; bind_socket = "127.0.0.1:11335"; count = 1; secure_ip = "127.0.0.1"; }
worker {
  type = "rspamd_proxy"; bind_socket = "127.0.0.1:11336"; count = 1;
  milter = true; allow_file_and_shm_inputs = false;
  upstream { scanner { hosts = "127.0.0.1:18080"; default = true; } }
}
''')
    forwarding = Router(('127.0.0.1', 18080), Route)
    threading.Thread(target=forwarding.serve_forever, daemon=True).start()
    with (WORK / 'stdout').open('w') as output:
        process = subprocess.Popen(['/opt/rspamd/bin/rspamd', '-f', '--insecure',
                                    '--var=DBDIR=/tmp/postfix-data', '-c', str(config)],
                                   stdout=output, stderr=subprocess.STDOUT)
    try:
        for port in (11333, 11334, 11335, 11336):
            wait_port(port, process)
        first, _ = transaction('different-workers')
        print('PASS DATA and EOM use different scanner processes', first['data_pid'], first['pid'], flush=True)

        def restart():
            os.kill(first['pid'], signal.SIGKILL)
            deadline = time.monotonic() + 20
            while Path(f"/proc/{first['pid']}").exists():
                assert time.monotonic() < deadline, 'old worker did not exit'
                time.sleep(.05)
            wait_port(11334, process)

        restarted, _ = transaction('restart-between-passes', between=restart)
        assert restarted['pid'] != first['pid']
        print('PASS scanner restart between DATA and EOM', flush=True)

        old_workers = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()

        def reload():
            os.kill(process.pid, signal.SIGHUP)
            deadline = time.monotonic() + 20

            # Wait for the new scanner generation, keeping the original
            # transaction's DATA record and proxy connection alive.
            while time.monotonic() < deadline:
                probe, _ = transaction('reload-probe', False)
                if probe['pid'] != restarted['pid']:
                    return
                time.sleep(.05)
            raise AssertionError('reload did not replace the EOM scanner')

        reloaded, _ = transaction('reload-between-passes', between=reload)
        assert reloaded['pid'] != restarted['pid'], reloaded
        print('PASS reload during a continuing transaction', reloaded['pid'], flush=True)

        for label, counter in (('observer-slow', 'observer_timeout'), ('observer-error', 'observer_error')):
            before = stats()
            started = time.monotonic()
            client = envelope(label, 'blocked.example.test')
            try:
                assert client.data() == b'r'
            finally:
                client.close()
            assert time.monotonic() - started < 2, label
            assert stats()[counter] == before[counter] + 1, (label, stats())
            print('PASS frozen rejection survives', label, flush=True)

        # Exclude draining workers from the before/after CPU and RSS snapshots.
        deadline = time.monotonic() + 20
        while any(Path('/proc/' + pid).exists() for pid in old_workers):
            assert time.monotonic() < deadline, 'old workers did not drain after reload'
            time.sleep(.05)

        # Warm both routes; report measurements without brittle timing thresholds.
        transaction('warm-eom', False)
        transaction('warm-data', True)
        benchmark(process, False)
        benchmark(process, True)
    except Exception:
        for name in ('stdout', 'rspamd.log'):
            print(name, (WORK / name).read_text()[-20000:], flush=True)
        raise
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        forwarding.shutdown()
        forwarding.server_close()


if __name__ == '__main__':
    main()
