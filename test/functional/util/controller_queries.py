#!/usr/bin/env python3
"""Exercise controller query ownership over real, untrusted TCP connections."""
import argparse
from contextlib import closing
import http.client
import json
import os
import re
import shutil
import signal
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from reload_leaks import compare, leak_reports

CASES = ('read-empty', 'read-values', 'write-empty', 'write-values', 'custom')


def request(port, case):
    headers = {}
    if case.startswith('read'):
        path = '/auth'
    elif case.startswith('write'):
        path = '/saveactions'
    else:
        # A real C custom command consumes Flag after the query table is freed.
        # Flag 17 intentionally has no matching rule: no storage is contacted.
        path = '/fuzzydelhash?%46lag=0&%46lag=17&hash=abc%2Bdef&empty=&dup=old&dup=new'
        headers['Password'] = 'query-test-password'
    if case.endswith('values'):
        path += '?unused=value&empty='
    with closing(http.client.HTTPConnection('127.0.0.1', port, timeout=2)) as conn:
        conn.request('GET', path, headers=headers)
        response = conn.getresponse()
        body = response.read()
        if case.startswith('read'):
            assert response.status == 200, (response.status, body)
            assert json.loads(body)['read_only'] is True, body
        elif case.startswith('write'):
            # Authentication succeeded; the endpoint rejects the missing body.
            assert response.status == 400, (response.status, body)
            assert b'Empty body is not permitted' in body, body
        else:
            assert response.status == 404, (response.status, body)
            assert b'No fuzzy rules matched for flag 17' in body, body


def run_case(args, directory, iterations, sanitized):
    directory.mkdir()
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    password = ''
    if args.case.startswith('read'):
        password = 'enable_password = "configured-enable-password";'
    elif args.case == 'custom':
        password = 'password = "query-test-password"; enable_password = "query-test-password";'
    (directory / 'rspamd.conf').write_text(f'''
options {{
  filters = ["fuzzy_check"];
  pidfile = "{directory}/pid";
  tempdir = "{directory}";
  hs_cache_dir = "{directory}";
  url_tld = "{args.source}/test/lua/unit/test_tld.dat";
  dns {{ nameserver = "127.0.0.1"; }}
}}
logging {{ type = file; filename = "{directory}/worker.log";
  level = debug; debug_modules = ["hyperscan"]; }}
lang_detection {{ languages = "{args.source}/contrib/languages-data"; }}
actions {{ reject = 100; }}
worker "controller" {{
  bind_socket = "127.0.0.1:{port}"; count = 1; allow_file_and_shm_inputs = false;
  # No secure_ip: loopback must take the password/query authentication path.
  {password}
}}
fuzzy_check {{
  rule "query-test" {{
    servers = "127.0.0.1:1";
    symbol = "QUERY_TEST_RULE";
    read_only = false;
    skip_unknown = true;
    fuzzy_map {{ QUERY_TEST {{ flag = 1; }} }}
  }}
}}
''')
    env = os.environ.copy()
    env['LUA_PATH'] = str(args.source / 'contrib/lua-?/?.lua') + ';;'
    env['ASAN_OPTIONS'] = (env.get('ASAN_OPTIONS', '') +
                           ':detect_leaks=1:leak_check_at_exit=1:malloc_context_size=40:log_path=' + str(directory / 'asan'))
    if args.symbolizer:
        env['ASAN_OPTIONS'] += ':external_symbolizer_path=' + args.symbolizer
    env['LSAN_OPTIONS'] = 'exitcode=23'
    command = [str(args.rspamd), '-f', '-i', '-c', str(directory / 'rspamd.conf')]
    for key, value in {'LUALIBDIR': args.source / 'lualib', 'RULESDIR': args.source / 'rules',
                       'DBDIR': directory, 'RUNDIR': directory}.items():
        command += ['--var', key + '=' + str(value)]
    with (directory / 'output').open('w') as output:
        process = subprocess.Popen(command, env=env, stdout=output, stderr=output,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 15
            while True:
                assert process.poll() is None, f'daemon exited: {directory}'
                try:
                    request(port, args.case)
                    if 'hs_helper starting event loop' in (directory / 'worker.log').read_text():
                        break
                    if time.monotonic() >= deadline:
                        raise AssertionError('helper startup did not complete')
                    time.sleep(0.05)
                except (OSError, http.client.HTTPException):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            for _ in range(iterations):
                request(port, args.case)
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise AssertionError(f'graceful shutdown timed out: {directory}')
    assert process.returncode in (0, 23), f'exit {process.returncode}: {directory}'
    # Focus this regression on the query tables/strings owned by these two
    # handlers. Native OS startup reports remain in the saved raw logs; all
    # ASan memory-safety errors still fail, regardless of allocation origin.
    def controller_allocation(block):
        return any('in ' + name + ' ' in block for name in (
            'rspamd_controller_check_password', 'rspamd_controller_handle_custom'))

    return leak_reports(directory, process.pid, controller_allocation) if sanitized else []


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rspamd', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--iterations', type=int, default=128)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    args.rspamd = args.rspamd.resolve()
    args.source = args.source.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix=args.case + '-', dir=args.output_dir))
    version = subprocess.run([str(args.rspamd), '--version'], capture_output=True,
                             text=True, check=True)
    sanitized = 'ASAN enabled: TRUE' in version.stdout
    args.symbolizer = None
    if sanitized:
        configured = re.search(r'(?:^|:)external_symbolizer_path=([^:]+)',
                               os.environ.get('ASAN_OPTIONS', ''))
        candidate = (configured[1] if configured else
                     os.environ.get('ASAN_SYMBOLIZER_PATH', 'llvm-symbolizer'))
        args.symbolizer = shutil.which(candidate)
        if not args.symbolizer:
            parser.error('ASan query checks need llvm-symbolizer in PATH or '
                         'ASAN_OPTIONS=external_symbolizer_path=/path/to/llvm-symbolizer')
    baseline = run_case(args, directory / 'baseline', 0, sanitized)
    changed = run_case(args, directory / 'requests', args.iterations, sanitized)
    regressions = compare(baseline, changed)
    summary = {'case': args.case, 'requests': args.iterations, 'sanitized': sanitized,
               'regressions': regressions}
    (directory / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    print('Logs: ' + str(directory))
    return bool(regressions)


if __name__ == '__main__':
    raise SystemExit(main())
