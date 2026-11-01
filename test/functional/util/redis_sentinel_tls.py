#!/usr/bin/env python3
"""Exercise independent Sentinel/data TLS, discovery and real primary failover."""

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request


class Redis:
    def __init__(self, port, user, password, cert=None):
        self.sock = socket.create_connection(('127.0.0.1', port), timeout=2)
        if cert:
            context = ssl.create_default_context(cafile=str(cert))
            context.load_cert_chain(str(cert), str(cert.with_suffix('.key')))
            self.sock = context.wrap_socket(self.sock, server_hostname='localhost')
        self.file = self.sock.makefile('rb')
        self.command('AUTH', user, password)

    def close(self):
        self.file.close()
        self.sock.close()

    def read(self):
        kind, line = self.file.read(1), self.file.readline().rstrip(b'\r\n')
        if kind == b'+':
            return line.decode()
        if kind == b'-':
            raise RuntimeError(line.decode())
        if kind == b':':
            return int(line)
        if kind == b'$':
            size = int(line)
            if size < 0:
                return None
            data = self.file.read(size)
            assert self.file.read(2) == b'\r\n'
            return data.decode()
        if kind == b'*':
            return [self.read() for _ in range(int(line))]
        raise RuntimeError('invalid or closed Redis connection')

    def command(self, *args):
        parts = [str(arg).encode() for arg in args]
        request = b'*%d\r\n' % len(parts)
        request += b''.join(b'$%d\r\n' % len(p) + p + b'\r\n' for p in parts)
        self.sock.sendall(request)
        return self.read()


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_for(callback, description, timeout=20):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            result = callback()
            if result:
                return result
            last = 'callback did not report success'
        except (OSError, RuntimeError, ValueError) as error:
            last = error
        time.sleep(.05)
    raise AssertionError(f'timeout waiting for {description}: {last}')


def run(command, env=None):
    result = subprocess.run(list(map(str, command)), capture_output=True, text=True,
                            env=env, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def certificate(openssl, path):
    run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
         '-keyout', path.with_suffix('.key'), '-out', path, '-days', '1',
         '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'])


def scenario(args, root, server, data_tls, sentinel_tls, failover):
    root.mkdir(parents=True, exist_ok=True)
    data_cert, sentinel_cert = root / 'data.pem', root / 'sentinel.pem'
    certificate(args.openssl, data_cert)
    certificate(args.openssl, sentinel_cert)
    bundle = root / 'ca-bundle.pem'
    bundle.write_bytes(data_cert.read_bytes() + sentinel_cert.read_bytes())
    primary, replica, sentinel, scanner = port(), port(), port(), port()
    processes, logs = [], []
    env = os.environ.copy()
    for name in ('LUA_PATH', 'LUALIBDIR', 'RULESDIR', 'DYLD_LIBRARY_PATH'):
        env.pop(name, None)

    def start(command, name):
        output = (root / (name + '.output')).open('w')
        logs.append(output)
        process = subprocess.Popen(list(map(str, command)), env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(process)
        return process

    def query(endpoint, *command, sent=False):
        cert = sentinel_cert if sent and sentinel_tls else data_cert if not sent and data_tls else None
        client = Redis(endpoint, 'sentinel-user' if sent else 'data-user',
                       'sentinel-password' if sent else 'data-password', cert)
        try:
            if not sent:
                client.command('SELECT', 3)
            return client.command(*command)
        finally:
            client.close()

    def connection(cert):
        return (f'ssl=true; ssl_ca="{cert}"; ssl_cert="{cert}"; '
                f'ssl_key="{cert.with_suffix(".key")}"; sni="localhost";')

    try:
        for name, endpoint in (('primary', primary), ('replica', replica)):
            directory = root / name
            directory.mkdir()
            transport = f'port {endpoint}'
            if data_tls:
                transport = (f'port 0\ntls-port {endpoint}\ntls-cert-file {data_cert}\n'
                             f'tls-key-file {data_cert.with_suffix(".key")}\n'
                             f'tls-ca-cert-file {data_cert}\ntls-auth-clients yes\n'
                             'tls-replication yes')
            replication = ''
            if name == 'replica':
                replication = (f'replicaof 127.0.0.1 {primary}\nmasteruser data-user\n'
                               f'masterauth data-password\nreplica-announce-port {replica}')
            config = directory / 'redis.conf'
            config.write_text(f'''bind 127.0.0.1
{transport}
user default off
user data-user on >data-password ~* &* +@all
save ""
appendonly no
repl-diskless-sync-delay 0
dir {directory}
{replication}
''')
            process = start([server, config], name)
            try:
                wait_for(lambda p=endpoint: query(p, 'PING') == 'PONG', name, 5)
            except AssertionError:
                output = (root / (name + '.output')).read_text()
                if data_tls and ('TLS' in output or 'tls-' in output) and process.poll() is not None:
                    raise NotImplementedError('Redis server lacks required TLS support: ' + output)
                raise

        wait_for(lambda: 'master_link_status:up' in query(replica, 'INFO', 'replication'), 'replication')
        transport = f'port {sentinel}'
        if sentinel_tls or data_tls:
            transport += (f'\ntls-cert-file {sentinel_cert}\n'
                          f'tls-key-file {sentinel_cert.with_suffix(".key")}\n'
                          f'tls-client-cert-file {data_cert}\n'
                          f'tls-client-key-file {data_cert.with_suffix(".key")}\n'
                          f'tls-ca-cert-file {bundle}\ntls-auth-clients yes')
        if sentinel_tls:
            transport = f'port 0\ntls-port {sentinel}\n' + transport.split('\n', 1)[1]
        if data_tls:
            transport += '\ntls-replication yes'
        config = root / 'sentinel.conf'
        config.write_text(f'''bind 127.0.0.1
{transport}
user default off
user sentinel-user on >sentinel-password ~* &* +@all
dir {root}
sentinel monitor mymaster 127.0.0.1 {primary} 1
sentinel auth-user mymaster data-user
sentinel auth-pass mymaster data-password
sentinel down-after-milliseconds mymaster 1000
sentinel failover-timeout mymaster 5000
sentinel parallel-syncs mymaster 1
''')
        start([server, config, '--sentinel'], 'sentinel')
        wait_for(lambda: query(sentinel, 'SENTINEL', 'replicas', 'mymaster', sent=True), 'Sentinel discovery')

        options = f'''servers="127.0.0.1:1"; username="data-user";
password="data-password"; db="3"; timeout=1;
{connection(data_cert) if data_tls else 'ssl=false;'}
sentinels="127.0.0.1:{sentinel}"; sentinel_watch_time=0.1;
sentinel_masters_pattern="^mymaster$";
sentinel {{ username="sentinel-user"; password="sentinel-password"; timeout=1;
{connection(sentinel_cert) if sentinel_tls else 'ssl=false;'} }}'''
        sync = root / 'sync.lua'
        sync.write_text('''
local lr = require 'lua_redis'
local ucl = require 'ucl'
local parser = ucl.parser()
assert(parser:parse_string([==[%s]==]))
local params = assert(lr.try_load_redis_servers(parser:get_object(), rspamd_config, true))
local id = lr.add_redis_script('return redis.call("INCR",KEYS[1])', params)
local error
lr.prepare_redis_setup(params, function(err) error = err end)
assert(not error, error)
local ok, conn = lr.redis_connect_sync(params, true)
assert(ok, tostring(conn))
conn:add_cmd('INCR', {'sentinel-sync'})
local success, result = conn:exec()
assert(success and result > 0, tostring(result))
print('SENTINEL_SYNC_OK ' .. params.write_servers_str)
''' % options)
        output = run([args.rspamadm, 'lua', '-b', sync], env)
        assert f'SENTINEL_SYNC_OK 127.0.0.1:{primary}' in output, output

        probe = root / 'probe.lua'
        probe.write_text('''
local lr = require 'lua_redis'
local params = assert(lr.parse_redis_server('sentinel_probe'))
local id = lr.add_redis_script('return redis.call("INCR",KEYS[1])', params)
rspamd_config:register_symbol{
  name='SENTINEL_PROBE',
  callback=function(task)
    lr.exec_redis_script(id, {task=task, is_write=true}, function(err, data)
      if not err then task:insert_result('SENTINEL_PROBE', 1, tostring(data)) end
    end, {'sentinel-async'}, {})
  end,
}
''')
        config = root / 'rspamd.conf'
        config.write_text(f'''
options {{ filters=[]; pidfile="{root}/pid"; control_socket="{root}/control";
  url_tld="{args.source}/test/lua/unit/test_tld.dat"; }}
logging {{ type=file; filename="{root}/rspamd.log"; level=debug; }}
worker "normal" {{ bind_socket="127.0.0.1:{scanner}"; count=1; task_timeout=5s; }}
sentinel_probe {{ {options} }}
lua="{probe}";
''')
        start([args.rspamd, '-f', '--insecure', '-c', config], 'rspamd')

        def scan():
            request = urllib.request.Request(f'http://127.0.0.1:{scanner}/checkv2',
                                             data=b'Subject: Sentinel test\r\n\r\nprobe\r\n')
            with urllib.request.urlopen(request, timeout=7) as reply:
                symbols = json.load(reply).get('symbols', {})
                return symbols.get('SENTINEL_PROBE')

        result = wait_for(scan, 'worker discovery and script upload')
        if failover:
            before = query(primary, 'GET', 'sentinel-async')
            wait_for(lambda: query(replica, 'GET', 'sentinel-async') == before,
                     'replica data')
            query(sentinel, 'SENTINEL', 'failover', 'mymaster', sent=True)
            wait_for(lambda: query(sentinel, 'SENTINEL', 'get-master-addr-by-name', 'mymaster', sent=True)[1]
                     == str(replica), 'primary promotion', 25)
            # GET-MASTER-ADDR can expose the promoted replica before MASTERS
            # switches its advertised address at the end of the failover.
            wait_for(lambda: any(dict(zip(m[::2], m[1::2])).get('port') == str(replica)
                                 for m in query(sentinel, 'SENTINEL', 'masters', sent=True)),
                     'Sentinel topology convergence')
            output = run([args.rspamadm, 'lua', '-b', sync], env)
            assert f'SENTINEL_SYNC_OK 127.0.0.1:{replica}' in output, output
            wait_for(lambda: f'replace write servers with new list: 127.0.0.1:{replica}'
                     in (root / 'rspamd.log').read_text(), 'worker topology refresh')
            result = wait_for(scan, 'script execution after failover')
            assert int(result['options'][0]) > int(before), 'counter did not survive failover'

        if sentinel_tls:
            bad = root / 'untrusted.lua'
            bad.write_text(sync.read_text().replace(f'ssl_ca="{sentinel_cert}"', f'ssl_ca="{data_cert}"'))
            result = subprocess.run([str(args.rspamadm), 'lua', '-b', str(bad)], env=env,
                                    capture_output=True, text=True, timeout=10)
            assert result.returncode != 0, 'untrusted Sentinel certificate accepted'
        assert 'detected use-after-free' not in (root / 'rspamd.log').read_text()
        print(f'data_tls={data_tls} sentinel_tls={sentinel_tls} failover={failover}: PASS', flush=True)
    except Exception:
        for path in root.glob('*.output'):
            print(f'{path.name}:\n{path.read_text()[-4000:]}', file=sys.stderr)
        log = root / 'rspamd.log'
        if log.exists():
            print(log.read_text()[-6000:], file=sys.stderr)
        raise
    finally:
        for process in reversed(processes):
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
        for log in logs:
            log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rspamd', required=True, type=Path)
    parser.add_argument('--rspamadm', required=True, type=Path)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--redis-server', default=shutil.which('redis-server') or shutil.which('valkey-server'))
    parser.add_argument('--openssl', default=shutil.which('openssl'))
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    if not args.redis_server or not args.openssl:
        print('Redis/Valkey server and openssl are required')
        return 77
    # Keep Unix socket paths below the macOS sockaddr_un limit.
    with tempfile.TemporaryDirectory(prefix='rspamd-sentinel-', dir='/tmp') as temporary:
        root = args.output_dir or Path(temporary)
        root.mkdir(exist_ok=True, parents=True)
        try:
            for data_tls, sentinel_tls, failover in ((True, True, True), (False, True, False), (True, False, False)):
                scenario(args, root / f'data-{data_tls}-sentinel-{sentinel_tls}', args.redis_server,
                         data_tls, sentinel_tls, failover)
        except NotImplementedError as error:
            print(error)
            return 77
    return 0


if __name__ == '__main__':
    sys.exit(main())
