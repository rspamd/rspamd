#!/usr/bin/env python3
"""Verify same-startup recovery of regexp map and multipattern HS caches."""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def has_hyperscan(rspamadm):
    probe = subprocess.run([
        str(rspamadm), 'lua', '-b', '-e',
        "print('HS_CACHE_SUPPORTED=' .. tostring(require('rspamd_trie').has_hyperscan()))",
    ], check=True, capture_output=True, text=True)
    if 'HS_CACHE_SUPPORTED=false' in probe.stdout:
        return False
    assert 'HS_CACHE_SUPPORTED=true' in probe.stdout, probe.stdout + probe.stderr
    return True


def run_startup(rspamd, source, directory, delayed, postfork):
    log = directory / 'worker.log'
    log.write_text('')
    script = directory / 'test.lua'
    script.write_text('''
local hs_cache = require 'lua_hs_cache'
local create_backend = hs_cache.create_backend
hs_cache.create_backend = function(config)
  local backend = create_backend(config)
  if %s then
    local load = backend.load_async
    backend.load_async = function(self, key, platform, callback)
      load(self, key, platform, function(err, data)
        config.rspamd_config:add_periodic(config.ev_base, 0.01, function()
          callback(err, data)
          return false
        end, false)
      end)
    end
  end
  return backend
end
if %s then
  rspamd_config:add_on_load(function(config, ev_base, worker)
    local name = worker:get_name()
    if name ~= 'controller' and name ~= 'normal' then return end
    config:add_periodic(ev_base, 0.01, function()
      local file = assert(io.open('%s/ready-' .. name, 'w'))
      file:close()
      return false
    end, false)
  end)
end
local map = rspamd_config:add_map{
  url = '%s/patterns.map',
  type = 'regexp',
}
rspamd_config:register_symbol{
  name = 'HS_CACHE_RECOVERY',
  callback = function() return map:get_key('probe0001') ~= nil end,
}
''' % ('true' if delayed else 'false', 'true' if postfork else 'false',
       directory, directory))
    patterns = ''.join('/probe%04d/ value%d\n' % (i, i) for i in range(150))
    map_file = directory / 'patterns.map'
    map_file.write_text('' if postfork else patterns)
    ready_files = [directory / ('ready-' + name) for name in ('normal', 'controller')]
    for ready in ready_files:
        if ready.exists():
            ready.unlink()
    config = directory / 'rspamd.conf'
    config.write_text('''
options {
  filters = [];
  hs_cache_dir = "%s/cache";
  pidfile = "%s/pid";
  control_socket = "%s/control";
  map_watch_interval = 0.1s;
  dns { nameserver = "127.0.0.1"; }
  url_tld = "%s/test/lua/unit/test_tld.dat";
}
logging {
  type = file; filename = "%s"; level = debug;
  debug_modules = ["hyperscan", "map"];
}
lang_detection { languages = "%s/contrib/languages-data"; }
actions { reject = 100; }
worker "normal" { bind_socket = "%s/normal"; count = 1; }
worker "controller" { bind_socket = "%s/controller"; count = 1; }
worker "hs_helper" { cache_dir = "%s/cache"; cache_backend = file; }
lua = "%s";
''' % (directory, directory, directory, source, log, source,
       directory, directory, directory, script))
    env = os.environ.copy()
    for key in ('LUA_PATH', 'LUALIBDIR', 'RULESDIR', 'RSPAMADM'):
        env.pop(key, None)
    env['LUA_PATH'] = str(source / 'contrib/lua-?/?.lua') + ';;'
    command = [str(rspamd), '-f', '-i', '-c', str(config),
               '--var', 'LUALIBDIR=' + str(source / 'lualib'),
               '--var', 'RULESDIR=' + str(source / 'rules')]
    with (directory / 'output').open('w') as output:
        process = subprocess.Popen(command, env=env, stdout=output,
                                   stderr=output, start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            map_written = not postfork
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace')
                if process.poll() is not None:
                    raise AssertionError(text + (directory / 'output').read_text())
                # Publish only after both event loops have installed their file watches.
                if not map_written and all(ready.exists() for ready in ready_files):
                    map_file.write_text(patterns)
                    map_written = True
                # Both workers must load the map and all four stopword groups.
                if (text.count('loaded hyperscan database from cache backend for') >= 2
                        and text.count('hot-swapped to hyperscan (backend)') >= 8):
                    return text
                time.sleep(0.05)
            raise AssertionError('databases did not recover in this startup:\n' + text)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()


def corrupt_versions(rspamadm, directory, files):
    script = directory / 'corrupt.lua'
    script.write_text('''
local util = require 'rspamd_util'
local cryptobox = require 'rspamd_cryptobox'
local function le32(value)
  local bytes = {}
  for i = 1, 4 do
    bytes[i] = string.char(value %% 256)
    value = math.floor(value / 256)
  end
  return table.concat(bytes)
end
for _, filename in ipairs{%s} do
  local file = assert(io.open(filename, 'rb'))
  local compressed = file:read('*a')
  file:close()
  local err, data = util.zstd_decompress(compressed)
  assert(not err, err)
  data = tostring(data)
  local header = data:sub(1, 8) == 'rshsre12'
  local blob = header and data:sub(53) or data
  blob = blob:sub(1, 4) .. string.char((blob:byte(5) + 1) %% 256) .. blob:sub(6)
  if header then
    -- Multipattern headers have a 32-byte platform, zero IDs, and an 8-byte CRC.
    assert(data:sub(41, 44) == string.rep(string.char(0), 4))
    local hi, lo = cryptobox.fast_hash64(blob, 0xdeadbabe)
    data = data:sub(1, 44) .. le32(lo) .. le32(hi) .. blob
  else
    data = blob
  end
  file = assert(io.open(filename, 'wb'))
  file:write(data)
  file:close()
end
''' % ', '.join(json.dumps(str(file)) for file in files))
    subprocess.run([str(rspamadm), 'lua', '-b', str(script)],
                   check=True, capture_output=True, text=True)


def check_recovery(rspamd, rspamadm, source, delayed, postfork=False):
    with tempfile.TemporaryDirectory(prefix='hs-recovery-') as temporary:
        directory = Path(temporary)
        cache = directory / 'cache'
        cache.mkdir()
        run_startup(rspamd, source, directory, delayed, postfork)
        files = sorted(cache.glob('*.hs.zst'))
        assert len(files) == 5, files
        original = {file: file.read_bytes() for file in files}
        valid = run_startup(rspamd, source, directory, delayed, postfork)
        assert 'save_async: entity=' not in valid, valid
        assert all(file.read_bytes() == data for file, data in original.items())
        # Preserve the envelope and its CRC so Hyperscan itself rejects the version.
        # The file backend accepts uncompressed data with the .zst extension.
        corrupt_versions(rspamadm, directory, files)
        recovered = run_startup(rspamd, source, directory, delayed, postfork)
        assert recovered.count('save_async: entity=') == 5, recovered
        assert len(list(cache.glob('*.hs.zst'))) == 5
        valid = run_startup(rspamd, source, directory, delayed, postfork)
        assert 'save_async: entity=' not in valid, valid
        print('cache recovery passed (%s callbacks, %s map)' % (
            'delayed' if delayed else 'immediate', 'post-fork' if postfork else 'pre-fork'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rspamd', type=Path, required=True)
    parser.add_argument('--rspamadm', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    if not has_hyperscan(args.rspamadm):
        print('SKIP: Hyperscan is unavailable in this build or on this CPU')
        sys.exit(77)
    for delayed in (False, True):
        check_recovery(args.rspamd, args.rspamadm, args.source, delayed)
    check_recovery(args.rspamd, args.rspamadm, args.source, True, postfork=True)
