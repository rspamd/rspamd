#!/usr/bin/env python3
"""Check real reloads against per-process LeakSanitizer startup baselines."""
import argparse
from collections import Counter, defaultdict
from email.utils import formatdate
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

MESSAGE = (b'From: sender@example.com\r\nTo: recipient@example.com\r\n'
           b'Subject: reload\r\nContent-Type: text/plain\r\n\r\nreload probe\r\n')
TYPES = ('set', 'map', 'regexp', 'radix', 'callback')


def atomic_write(path, data):
    temporary = path.with_suffix(path.suffix + '.new')
    temporary.write_text(data)
    temporary.replace(path)


def bodies(generation):
    value = f'{generation:04d}'
    return {
        'set': ('even' if generation % 2 == 0 else 'odd') + '\n',
        'map': 'probe ' + value + '\n',
        'regexp': '/^probe$/ ' + value + '\n',
        'radix': '192.0.2.0/24 ' + value + '\n',
        'callback': value + '\n',
    }


class MapsServer:
    def __init__(self):
        self.generation = 0
        self.requests = Counter()
        self.fail_once = set()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                kind = self.path.lstrip('/')
                if kind not in TYPES:
                    self.send_error(404)
                    return
                generation = outer.generation
                if kind in outer.fail_once:
                    outer.fail_once.remove(kind)
                    outer.requests[(generation, kind, 503)] += 1
                    self.send_response(503)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                etag = f'"{generation:04d}"'
                code = 304 if self.headers.get('If-None-Match') == etag else 200
                outer.requests[(generation, kind, code)] += 1
                body = bodies(generation)[kind].encode() if code == 200 else b''
                self.send_response(code)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('ETag', etag)
                self.send_header('Expires', formatdate(time.time() + 2, usegmt=True))
                self.send_header('Cache-Control', 'max-age=0')
                self.end_headers()
                if self.command != 'HEAD':
                    self.wfile.write(body)

            do_HEAD = do_GET

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return 'http://127.0.0.1:' + str(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def lua_script(directory, urls, generation, inject_leak=False):
    injection = """
if config_generation ~= '0000' or lua_generation ~= '0000' then
  local ffi = require 'ffi'
  ffi.cdef[[void *malloc(size_t size);]]
  local p = ffi.cast('unsigned char *', ffi.C.malloc(12345))
  p[0] = 1
end
""" if inject_leak else ''
    maps = '\n'.join(f"local m_{kind} = assert(rspamd_config:add_map{{url={json.dumps(urls[kind])}, type='{kind}'}})"
                     for kind in TYPES if kind != 'callback')
    return fr'''
local util = require 'rspamd_util'
local config_generation = tostring(rspamd_config:get_all_opt('reload_probe').generation)
local lua_generation = '{generation:04d}'
{injection}
-- LuaJIT can also measure reachable pool storage, which LSan cannot see.
-- Other supported Lua runtimes still run the native leak checks.
local have_ffi, ffi = pcall(require, 'ffi')
local pool_bytes = function() return 'unavailable' end
if have_ffi then
  ffi.cdef[[
    typedef struct {{
      const char *src;
      uint32_t cur_suggestion, cur_elts, cur_vars, cur_dtors,
          avg_fragmentation, avg_leftover, samples;
      uint64_t pools_allocated, pools_freed, chunks_allocated,
          bytes_allocated_total, bytes_currently_used;
    }} reload_mempool_entry_stat;
    typedef void (*reload_mempool_entry_cb)(const reload_mempool_entry_stat *, void *);
    void rspamd_mempool_entries_foreach(reload_mempool_entry_cb cb, void *ud);
  ]]
  pool_bytes = function()
    local total = 0
    local callback = ffi.cast('reload_mempool_entry_cb', function(stat)
      total = total + tonumber(stat[0].bytes_currently_used)
    end)
    ffi.C.rspamd_mempool_entries_foreach(callback, nil)
    callback:free()
    return tostring(total)
  end
  require('jit').off(pool_bytes, true)
end
local callback_value = 'pending'
rspamd_config:add_config_unload(function()
  local file = assert(io.open({json.dumps(str(directory / 'unloads'))}, 'a'))
  file:write(util.get_pid(), ':', config_generation, ':', lua_generation, '\n')
  file:close()
end)
{maps}
assert(rspamd_config:add_map{{
  url = {json.dumps(urls['callback'])}, type = 'callback',
  callback = function(data) callback_value = tostring(data):match('(%d+)') or 'invalid' end,
}})
rspamd_config:register_symbol{{
  name = 'RELOAD_PROBE', score = 1.0,
  callback = function()
    collectgarbage('collect')
    return true, {{
      'config=' .. config_generation,
      'lua=' .. lua_generation,
      'pid=' .. util.get_pid(),
      'lua_kb=' .. collectgarbage('count'),
      'pool_bytes=' .. pool_bytes(),
      'set=' .. tostring(m_set:get_key('even')) .. '/' .. tostring(m_set:get_key('odd')),
      'map=' .. tostring(m_map:get_key('probe')),
      'regexp=' .. tostring(m_regexp:get_key('probe')),
      'radix=' .. tostring(m_radix:get_key('192.0.2.1')),
      'callback=' .. callback_value,
    }}
  end,
}}
'''


def config_text(directory, source, generation, sockets):
    return f'''
options {{
  filters = [];
  pidfile = "{directory}/pid";
  control_socket = "{sockets}/control";
  tempdir = "{directory}";
  hs_cache_dir = "{directory}/cache";
  maps_cache_dir = "{directory}/cache";
  map_watch_interval = 0.1s;
  map_file_watch_multiplier = 1.0;
  url_tld = "{source}/test/lua/unit/test_tld.dat";
  dns {{ nameserver = "127.0.0.1"; }}
}}
logging {{ type = file; filename = "{directory}/worker.log"; level = info;
  debug_ip = "{directory}/radix.map"; }}
lang_detection {{ languages = "{source}/contrib/languages-data"; }}
actions {{ reject = 100; }}
reload_probe {{ generation = "{generation:04d}"; }}
worker "normal" {{ bind_socket = "{sockets}/normal"; count = 1; }}
worker "controller" {{ bind_socket = "{sockets}/controller"; count = 1; }}
worker "hs_helper" {{ cache_dir = "{directory}/cache"; cache_backend = file; }}
lua = "{directory}/rule.lua";
'''


def scan(directory, worker):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        sock.connect(str(directory / worker))
        sock.sendall(b'POST /checkv2 HTTP/1.0\r\nContent-Length: ' + str(len(MESSAGE)).encode() + b'\r\n\r\n' + MESSAGE)
        response = http.client.HTTPResponse(sock)
        response.begin()
        body = response.read()
        if response.status != 200:
            raise AssertionError((response.status, body))
        reply = json.loads(body)
        return dict(option.split('=', 1) for option in reply['symbols']['RELOAD_PROBE']['options'])


def wait_scan(process, directory, expected, timeout=15):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f'master exited early: {process.returncode}')
        try:
            last = scan(directory, 'normal')
            owner = scan(directory, 'controller')
            if all(last.get(key) == value and owner.get(key) == value
                   for key, value in expected.items()):
                for key in ('pid', 'lua_kb', 'pool_bytes'):
                    last['controller_' + key] = owner[key]
                return last
            last['controller'] = owner
        except (OSError, http.client.HTTPException, ValueError, KeyError) as error:
            last = repr(error)
        time.sleep(0.05)
    raise AssertionError(f'changed state did not become visible: expected={expected}, got={last}')


def expected_state(config_generation=0, lua_generation=0, map_generation=0):
    return {
        'config': f'{config_generation:04d}', 'lua': f'{lua_generation:04d}',
        'set': 'true/false' if map_generation % 2 == 0 else 'false/true',
        **{kind: f'{map_generation:04d}' for kind in TYPES if kind != 'set'},
    }


def leak_reports(directory, master_pid, allocation_filter=None):
    roles = {master_pid: 'main'}
    log = (directory / 'worker.log').read_text(errors='replace')
    for pid, role in re.findall(r'#(\d+)\(([^)]+)\)', log):
        roles[int(pid)] = role
    reports = []
    for path in sorted(directory.glob('asan.*')):
        text = path.read_text(errors='replace')
        if ('ERROR: AddressSanitizer:' in text or 'runtime error:' in text or
                'AddressSanitizer:DEADLYSIGNAL' in text or 'LeakSanitizer has encountered a fatal error' in text):
            raise AssertionError(f'memory safety failure: {path}\n{text}')
        pid = int(path.name.rsplit('.', 1)[1])
        role = roles.get(pid)
        assert role, f'unidentified process in sanitizer report: {path}'
        allocations = Counter()
        parsed_bytes = parsed_objects = 0
        objects = Counter()
        startup_stacks = []
        for block in re.split(r'\n(?=(?:Direct|Indirect) leak of)', text):
            match = re.match(r'(Direct|Indirect) leak of (\d+) byte\(s\) in (\d+) object\(s\)', block)
            if not match:
                continue
            parsed_bytes += int(match[2])
            parsed_objects += int(match[3])
            frames = re.findall(r'^\s*#\d+ 0x[0-9a-f]+ (.+)$', block, re.M)
            # Module-relative offsets identify allocation sites across ASLR and
            # different temporary fixture directories. Four frames retain the
            # allocation origin without tying it to startup vs reload callers.
            sites = []
            for frame in frames[:4]:
                module = re.search(r'\(([^()]+)\)', frame)
                sites.append(Path(module[1]).name if module else frame)
            assert sites, f'unsymbolized allocation without frames: {path}'
            signature = (match[1], tuple(sites))
            # ASan can replace the inherited alternate signal stack after a
            # fork. The untracked original is a known startup-only allocation,
            # observed even without a reload. Keep it visible in the report,
            # and permit at most one per child; never hide a growing stack set.
            if (role != 'main' and 'in rspamd_set_crash_handler ' in block and
                    'in reread_config ' not in block and int(match[3]) == 1):
                startup_stacks.append({'bytes': int(match[2]), 'objects': int(match[3])})
                continue
            if allocation_filter is None or allocation_filter(block):
                allocations[signature] += int(match[2])
                objects[signature] += int(match[3])
        assert len(startup_stacks) <= 1, f'multiple inherited signal stacks: {path}'
        summary = re.search(r'SUMMARY: .*?: (\d+) byte\(s\) leaked in (\d+) allocation\(s\)', text)
        if 'ERROR: LeakSanitizer:' in text:
            assert summary, f'incomplete leak report: {path}'
            assert (parsed_bytes, parsed_objects) == tuple(map(int, summary.groups())), path
        reports.append({'pid': pid, 'role': role,
                        'allocations': allocations, 'objects': objects,
                        'startup_stacks': startup_stacks, 'path': str(path)})
    return reports


def run_case(args, directory, mode, iterations):
    directory.mkdir()
    sockets = args.socket_root / directory.name
    sockets.mkdir()
    (directory / 'cache').mkdir()
    server = MapsServer() if mode == 'http-maps' else None
    urls = {kind: server.url + '/' + kind if server else str(directory / (kind + '.map')) for kind in TYPES}
    for kind, body in bodies(0).items():
        atomic_write(directory / (kind + '.map'), body)
    atomic_write(directory / 'rule.lua', lua_script(directory, urls, 0, args.inject_leak))
    atomic_write(directory / 'rspamd.conf', config_text(directory, args.source, 0, sockets))
    env = os.environ.copy()
    for key in ('LUA_PATH', 'LUALIBDIR', 'RULESDIR', 'RSPAMADM'):
        env.pop(key, None)
    env['LUA_PATH'] = str(args.source / 'contrib/lua-?/?.lua') + ';;'
    env['ASAN_OPTIONS'] = env.get('ASAN_OPTIONS', '') + ':detect_leaks=1:leak_check_at_exit=1:log_path=' + str(directory / 'asan')
    env['LSAN_OPTIONS'] = 'exitcode=23'
    command = [str(args.rspamd), '-f', '-i', '-c', str(directory / 'rspamd.conf')]
    for key, value in {'LUALIBDIR': args.source / 'lualib', 'RULESDIR': args.source / 'rules',
                       'DBDIR': directory, 'RUNDIR': directory}.items():
        command += ['--var', key + '=' + str(value)]
    error = None
    samples = []
    rejected = 0
    with (directory / 'output').open('w') as output:
        process = subprocess.Popen(command, env=env, stdout=output, stderr=output, start_new_session=True)
        try:
            state = wait_scan(process, sockets, expected_state())
            for _ in range(3):
                state = wait_scan(process, sockets, expected_state())
            first_pid = state['pid']
            first_controller_pid = state['controller_pid']
            samples.append(state)
            if server:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    if all(server.requests[(0, kind, 304)] for kind in TYPES):
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError('HTTP fixtures did not exercise conditional 304 replies')
            for generation in range(1, iterations + 1):
                if generation % 3 == 0 and mode in ('config', 'lua'):
                    # A rejected reload must free the temporary configuration,
                    # keep the old workers, and preserve the last good rules.
                    target = directory / ('rspamd.conf' if mode == 'config' else 'rule.lua')
                    original = target.read_text()
                    atomic_write(target, original + ('\ninvalid = {' if mode == 'config' else '\nfunction ('))
                    config_file = directory / 'rspamd.conf'
                    original_config = config_file.read_text()
                    if mode == 'lua':
                        # Opening a different log makes restoring the global
                        # default logger observable, in addition to its leak.
                        atomic_write(config_file, original_config.replace(
                            str(directory / 'worker.log'), str(directory / 'rejected.log')))
                    rejected_before = (directory / 'worker.log').read_text().count('cannot parse new config file')
                    process.send_signal(signal.SIGHUP)
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        if (directory / 'worker.log').read_text().count('cannot parse new config file') > rejected_before:
                            break
                        if process.poll() is not None:
                            raise AssertionError('master exited during rejected reload')
                        time.sleep(0.05)
                    else:
                        raise AssertionError('invalid reload was not rejected')
                    preserved = wait_scan(process, sockets, {k: state[k] for k in expected_state()})
                    assert preserved['pid'] == state['pid'], 'rejected reload replaced the worker'
                    assert preserved['controller_pid'] == state['controller_pid']
                    atomic_write(target, original)
                    if mode == 'lua':
                        atomic_write(config_file, original_config)
                    rejected += 1
                if server and generation % 3 == 0:
                    server.fail_once = set(TYPES)
                    deadline = time.monotonic() + 15
                    while server.fail_once and time.monotonic() < deadline:
                        time.sleep(0.05)
                    assert not server.fail_once, 'HTTP error cases were not exercised'
                    preserved = wait_scan(process, sockets, {k: state[k] for k in expected_state()})
                    assert preserved['pid'] == state['pid']
                    assert preserved['controller_pid'] == state['controller_pid']
                if mode == 'config':
                    atomic_write(directory / 'rspamd.conf', config_text(directory, args.source, generation, sockets))
                    process.send_signal(signal.SIGHUP)
                    expected = expected_state(config_generation=generation)
                elif mode == 'lua':
                    atomic_write(directory / 'rule.lua', lua_script(directory, urls, generation, args.inject_leak))
                    process.send_signal(signal.SIGHUP)
                    expected = expected_state(lua_generation=generation)
                else:
                    for kind, body in bodies(generation).items():
                        atomic_write(directory / (kind + '.map'), body)
                    if server:
                        server.generation = generation
                    expected = expected_state(map_generation=generation)
                state = wait_scan(process, sockets, expected)
                if mode in ('maps', 'http-maps'):
                    # Map callbacks and HS cache work can still be unwinding.
                    # Observe several full-GC passes after the new state is
                    # visible, rather than mistaking a temporary buffer for
                    # retained Lua memory.
                    settled = [state]
                    for _ in range(5):
                        time.sleep(0.1)
                        settled.append(wait_scan(process, sockets, expected))
                    state = settled[-1]
                    for prefix in ('', 'controller_'):
                        key = prefix + 'lua_kb'
                        state[key] = str(min(float(s[key]) for s in settled))
                if mode in ('config', 'lua'):
                    token = (f'{process.pid}:{generation - 1:04d}:0000' if mode == 'config'
                             else f'{process.pid}:0000:{generation - 1:04d}')
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        unloads = directory / 'unloads'
                        if unloads.exists() and token in unloads.read_text().splitlines():
                            break
                        time.sleep(0.05)
                    else:
                        raise AssertionError(f'old configuration was not freed in master: {token}')
                if mode in ('maps', 'http-maps'):
                    assert state['pid'] == first_pid, 'map check restarted the worker'
                    assert state['controller_pid'] == first_controller_pid
                else:
                    assert state['pid'] != first_pid, 'config check did not replace the worker'
                    assert state['controller_pid'] != first_controller_pid
                    first_pid = state['pid']
                    first_controller_pid = state['controller_pid']
                samples.append(state)
                print(f'{mode}: changed generation {generation:04d} visible (pid {state["pid"]})', flush=True)
            if server:
                for generation in range(iterations + 1):
                    assert all(server.requests[(generation, kind, 200)] > 0 for kind in TYPES)
        except BaseException as caught:
            error = caught
        finally:
            process.terminate()
            try:
                process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                error = error or AssertionError('graceful shutdown timed out')
            if server:
                (directory / 'http-requests.json').write_text(json.dumps({str(k): v for k, v in server.requests.items()}, indent=2))
                server.close()
    if error:
        raise AssertionError(f'{mode}: {error}; logs: {directory}') from error
    assert process.returncode in (0, 23), f'exit {process.returncode}: {directory}'
    reports = leak_reports(directory, process.pid)
    # Fixed-size fixtures should not retain a pool per reload. Allow 32 KiB
    # for allocator warmup/counter rounding, much less than one error log.
    steady = samples[2:]
    # Compare the final Lua heap with its low-water mark: async compilation
    # can temporarily retain buffers even immediately after a full GC.
    for prefix in ('', 'controller_'):
        pool_values = [int(s[prefix + 'pool_bytes']) for s in steady
                       if s[prefix + 'pool_bytes'] != 'unavailable']
        if pool_values:
            assert max(pool_values) - min(pool_values) <= 32768, f'{prefix}pool storage grew: {pool_values}'
        if mode in ('maps', 'http-maps') and steady:
            lua_values = [float(s[prefix + 'lua_kb']) for s in steady]
            assert lua_values[-1] - min(lua_values) <= 64, f'{prefix}Lua heap grew after GC: {lua_values}'
    return {'reports': reports, 'samples': samples, 'rejected_reloads': rejected,
            'http_requests': {str(k): v for k, v in server.requests.items()} if server else {}}


def compare(baseline, changed):
    allowances = defaultdict(Counter)
    object_allowances = defaultdict(Counter)
    for report in baseline:
        allowance = allowances[report['role']]
        for signature, size in report['allocations'].items():
            allowance[signature] = max(allowance[signature], size)
            object_allowances[report['role']][signature] = max(object_allowances[report['role']][signature], report['objects'][signature])
    regressions = []
    for report in changed:
        for signature, size in report['allocations'].items():
            extra = size - allowances[report['role']][signature]
            extra_objects = report['objects'][signature] - object_allowances[report['role']][signature]
            if extra > 0 or extra_objects > 0:
                regressions.append({'role': report['role'], 'pid': report['pid'],
                                    'extra_bytes': max(0, extra), 'extra_objects': max(0, extra_objects), 'allocation_site': signature,
                                    'report': report['path']})
    return regressions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rspamd', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--mode', choices=('config', 'maps', 'http-maps', 'lua'), required=True)
    parser.add_argument('--iterations', type=int, default=8)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--inject-leak', action='store_true', help='diagnostic negative control: deliberately leak native memory on config/Lua reload')
    args = parser.parse_args()
    if args.iterations < 3:
        parser.error('--iterations must be at least 3 to cover rejection/recovery')
    if args.inject_leak and args.mode not in ('config', 'lua'):
        parser.error('--inject-leak requires config or lua mode')
    args.rspamd = args.rspamd.resolve()
    args.source = args.source.resolve()
    args.output_dir = args.output_dir.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir = Path(tempfile.mkdtemp(prefix='run-', dir=args.output_dir))
    version = subprocess.run([str(args.rspamd), '--version'], check=True, capture_output=True, text=True)
    if 'ASAN enabled: TRUE' not in version.stdout:
        print('SKIP: reload leak checks require an AddressSanitizer build')
        return 77
    # sockaddr_un is short (104 bytes on macOS); build paths can be much longer.
    with tempfile.TemporaryDirectory(prefix='rld-', dir='/tmp') as socket_root:
        args.socket_root = Path(socket_root)
        baseline = run_case(args, args.output_dir / 'baseline', args.mode, 0)
        changed = run_case(args, args.output_dir / 'changed', args.mode, args.iterations)
    regressions = compare(baseline['reports'], changed['reports'])
    report = {'mode': args.mode, 'iterations': args.iterations,
              'baseline_process_reports': len(baseline['reports']),
              'changed_process_reports': len(changed['reports']),
              'baseline_bytes_by_role': {role: max(sum(r['allocations'].values()) for r in baseline['reports'] if r['role'] == role) for role in {r['role'] for r in baseline['reports']}},
              'startup_stack_reports': sum(bool(r['startup_stacks']) for r in changed['reports']),
              'samples': changed['samples'],
              'rejected_reloads': changed['rejected_reloads'],
              'http_requests': changed['http_requests'],
              'regressions': regressions}
    (args.output_dir / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2), flush=True)
    return bool(regressions)


if __name__ == '__main__':
    sys.exit(main())
