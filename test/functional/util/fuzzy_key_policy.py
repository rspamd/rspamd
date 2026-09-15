#!/usr/bin/env python3
"""Exercise fuzzy key/IP policy with real encrypted UDP and TCP commands.

Usage: python3 fuzzy_key_policy.py --rspamd BUILD/src/rspamd \
    --rspamadm BUILD/src/rspamadm/rspamadm
Requires libsodium, already a dependency of Rspamd. No production services used.
"""
import argparse
import ctypes as C
import ctypes.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest


class Wire:
    def __init__(self):
        self.lib = C.CDLL(ctypes.util.find_library('sodium'))
        self.lib.sodium_init()
        self.lib.crypto_stream_xchacha20_xor.argtypes = [C.c_void_p, C.c_void_p, C.c_ulonglong, C.c_void_p, C.c_void_p]
        self.lib.crypto_onetimeauth.argtypes = [C.c_void_p, C.c_void_p, C.c_ulonglong, C.c_void_p]

    def key(self):
        secret = os.urandom(32)
        public = C.create_string_buffer(32)
        assert self.lib.crypto_scalarmult_base(public, secret) == 0
        return public.raw, secret

    def shared(self, public, secret):
        raw, nm = C.create_string_buffer(32), C.create_string_buffer(32)
        assert self.lib.crypto_scalarmult(raw, secret, public) == 0
        assert self.lib.crypto_core_hchacha20(nm, bytes(16), raw, None) == 0
        return nm.raw

    def crypt(self, data, nonce, nm):
        # Rspamd consumes the first full ChaCha block for the Poly1305 key.
        data = bytes(64) + data
        out = C.create_string_buffer(len(data))
        assert self.lib.crypto_stream_xchacha20_xor(out, data, len(data), nonce, nm) == 0
        return out.raw[:32], out.raw[64:]

    def mac(self, data, key):
        out = C.create_string_buffer(16)
        assert self.lib.crypto_onetimeauth(out, data, len(data), key) == 0
        return out.raw

    def packet(self, server, tag, command=0, version=4):
        plain = struct.pack('<BBBBiI64s', version, command, 0, 1, 0, tag, bytes(64))
        plain += b'd\x0cpolicy.test.'
        if server is None:
            return plain, None
        public, secret = self.key()
        nm = self.shared(server[0], secret)
        nonce = os.urandom(24)
        key, encrypted = self.crypt(plain, nonce, nm)
        return b'rsfe' + server[0][:8] + public + nonce + self.mac(encrypted, key) + encrypted, nm

    def reply(self, reply, nm):
        if nm is not None:
            nonce, mac, data = reply[:24], reply[24:40], reply[40:]
            key, reply = self.crypt(data, nonce, nm)
            assert self.mac(data, key) == mac, 'invalid reply MAC'
        return struct.unpack('<iIIf', reply[:16])


class PolicyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wire = Wire()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='fuzzy-key-policy-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.tag = 0
        self.keys = {name: self.wire.key() for name in ('shared', 'customer', 'limited', 'expired', 'write_only', 'ip_bound')}
        self.proc = None

    def start(self, dynamic=False):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        entries = {}
        for name, (pub, secret) in self.keys.items():
            ext = {'name': name, 'max_ips': 32}
            if name == 'limited':
                ext['ratelimit'] = {'rate': 0.001, 'burst': 0.5}
            elif name == 'expired':
                ext['expire'] = '01-01-2000'
            elif name == 'write_only':
                ext['allowed_ops'] = ['write']
            elif name == 'ip_bound':
                ext['skip_ip_checks'] = False
            entries[name] = {'pubkey': pub.hex(), 'privkey': secret.hex(), 'encoding': 'hex', 'type': 'kex', 'extensions': ext}
        (self.path / 'keys').write_text(json.dumps([v for k, v in entries.items() if k != 'shared']))
        (self.path / 'blocked').write_text('127.0.0.1\n' if not dynamic else '')
        # Telemetry and a dynamic ban are installed before traffic is admitted.
        (self.path / 'hooks.lua').write_text('''
rspamd_config:add_on_load(function(_, _, worker)
  if worker:get_name() ~= 'fuzzy' then return end
  %s
  worker:add_fuzzy_pre_handler(function(_, cmd)
    if cmd == 99 then return true, 0, 0 end
  end)
  worker:add_fuzzy_pre_handler(function(_, cmd, _, _, ext)
    local f = assert(io.open('%s/seen', 'a'))
    f:write(tostring(cmd), ':', tostring(ext.domain), '\\n')
    f:close()
  end)
end)
''' % ("assert(worker:block_fuzzy_client('127.0.0.1', 32, 0, 'test', 403))" if dynamic else '', self.path))
        config = f'''
logging {{ type = "file"; filename = "{self.path}/worker.log"; level = "info"; }}
options {{ pidfile = "{self.path}/pid"; control_socket = "{self.path}/control"; tempdir = "{self.path}"; }}
lua = "{self.path}/hooks.lua";
worker "fuzzy" {{
  bind_socket = "127.0.0.1:{self.port}"; count = 1;
  backend = "sqlite"; hashfile = "{self.path}/fuzzy.db";
  keypair = {json.dumps(entries['shared'])};
  dynamic_keys_map = "{self.path}/keys";
  blocked = "{self.path}/blocked";
  allow_update = [];
}}
'''
        (self.path / 'rspamd.conf').write_text(config)
        output = open(self.path / 'output', 'w')
        self.addCleanup(output.close)
        self.proc = subprocess.Popen([ARGS.rspamd, '-f', '-i', '-c', str(self.path / 'rspamd.conf')], stdout=output, stderr=output, start_new_session=True)
        self.addCleanup(self.stop)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self.fail((self.path / 'output').read_text())
            try:
                stats = self.stats()
                if len(stats['keys']) == len(self.keys):
                    return
            except (OSError, subprocess.SubprocessError, ValueError, KeyError):
                pass
            time.sleep(0.05)
        self.fail('worker not ready: ' + (self.path / 'output').read_text())

    def stop(self):
        if self.proc and self.proc.poll() is None:
            os.killpg(self.proc.pid, signal.SIGTERM)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait()
        if (self.path / 'output').exists():
            self.assertNotIn('ERROR: AddressSanitizer', (self.path / 'output').read_text())

    def stats(self):
        res = subprocess.run([ARGS.rspamadm, 'control', '-j', '-s', str(self.path / 'control'), 'fuzzystat'], capture_output=True, text=True, timeout=3, check=True)
        data = json.loads(res.stdout)
        # Control replies are indexed by worker pid.
        def find(value):
            if isinstance(value, dict):
                if 'keys' in value:
                    return value
                for item in value.values():
                    result = find(item)
                    if result is not None:
                        return result
            elif isinstance(value, list):
                for item in value:
                    result = find(item)
                    if result is not None:
                        return result
        result = find(data)
        if result is None:
            raise ValueError(data)
        return result

    def exchange(self, name, tcp=False, denied=False, command=0, tamper=False, version=4, conn=None):
        self.tag += 1
        server = self.wire.key() if name == 'unknown' else self.keys.get(name)
        packet, nm = self.wire.packet(server, self.tag, command, version)
        if tamper:
            packet = packet[:-1] + bytes([packet[-1] ^ 1])
        own = conn is None
        sock = conn or socket.socket(type=socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
        sock.settimeout(0.25 if denied else 2)
        try:
            if own:
                sock.connect(('127.0.0.1', self.port))
            sock.sendall((struct.pack('<H', len(packet)) if tcp else b'') + packet)
            if denied:
                with self.assertRaises(socket.timeout):
                    sock.recv(4096)
                return
            if tcp:
                header = self.recv_exact(sock, 2)
                reply = self.recv_exact(sock, struct.unpack('<H', header)[0])
            else:
                reply = sock.recv(4096)
            value, _, tag, _ = self.wire.reply(reply, nm)
            self.assertEqual(tag, self.tag)
            return value
        finally:
            if own:
                sock.close()

    @staticmethod
    def recv_exact(sock, length):
        data = b''
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                raise AssertionError('TCP connection closed before reply')
            data += chunk
        return data

    def exercise(self, dynamic):
        self.start(dynamic)
        for tcp in (False, True):
            for version in (4, 5):
                self.assertEqual(self.exchange('customer', tcp=tcp, version=version), 0)
                self.exchange('shared', tcp=tcp, version=version, denied=True)
            self.exchange(None, tcp=tcp, denied=True)
            self.exchange('ip_bound', tcp=tcp, denied=True)
            self.exchange('customer', tcp=tcp, tamper=True, denied=True)
            self.exchange('unknown', tcp=tcp, denied=True)
            for command in (3, 4):
                self.exchange('shared', tcp=tcp, command=command, denied=True)
                self.assertEqual(self.exchange('customer', tcp=tcp, command=command), 0)
            self.assertEqual(self.exchange('expired', tcp=tcp), 503)
            self.assertEqual(self.exchange('write_only', tcp=tcp), 503)
        self.assertEqual(self.exchange('limited'), 0)
        self.assertEqual(self.exchange('limited', tcp=True), 403)
        self.assertEqual(self.exchange('customer'), 0)
        stats = self.stats()
        self.assertEqual(stats['blocked_requests'], 12)
        self.assertEqual(stats['decrypt_errors'], 4)
        by_name = {v.get('keypair', {}).get('extensions', {}).get('name', k): v for k, v in stats['keys'].items()}
        self.assertEqual(by_name['shared']['errors'], 8)
        self.assertEqual(by_name['shared']['ips']['127.0.0.1']['errors'], 8)
        self.assertEqual(by_name['unkeyed']['errors'], 2)
        self.assertEqual(by_name['customer']['checked'], 5)
        self.assertEqual(by_name['limited']['errors'], 1)
        seen = (self.path / 'seen').read_text().splitlines()
        self.assertEqual(len(seen), 27)
        self.assertTrue(all(line.endswith(':policy.test.') for line in seen))
        # A synthetic reply must not bypass the ban or skip later observers.
        self.exchange('shared', command=99, denied=True)
        self.assertTrue((self.path / 'seen').read_text().endswith('99:policy.test.\n'))
        # Re-evaluate the credential for every frame on an existing connection.
        with socket.create_connection(('127.0.0.1', self.port)) as conn:
            self.exchange('shared', tcp=True, denied=True, conn=conn)
            self.assertEqual(self.exchange('customer', tcp=True, conn=conn), 0)
            self.exchange('shared', tcp=True, denied=True, conn=conn)

    def test_static_ban(self):
        self.exercise(False)

    def test_dynamic_ban(self):
        self.exercise(True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rspamd', required=True)
    parser.add_argument('--rspamadm', required=True)
    ARGS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__] + remaining)
