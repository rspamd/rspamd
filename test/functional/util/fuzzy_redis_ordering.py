#!/usr/bin/env python3
"""Check fuzzy update ordering through a real worker and Redis backend."""

import argparse
import hashlib
import socket
import struct
import subprocess
import time


# The key list is specific to this test; no scan or database flush is needed.
VERIFY = """
for i, key in ipairs(KEYS) do
  if ARGV[1] == 'deleted' then
    if redis.call('EXISTS', key) ~= 0 then
      return 'hash ' .. i .. ' survived ADD then DEL'
    end
  else
    local v = redis.call('HMGET', key, 'F', 'V', 'F1', 'V1')
    if v[1] ~= ARGV[1] or v[2] ~= ARGV[2] or v[3] or v[4] then
      return 'hash ' .. i .. ': expected flag=' .. ARGV[1] ..
          ', weight=' .. ARGV[2] .. ', got flag=' .. tostring(v[1]) ..
          ', weight=' .. tostring(v[2])
    end
  end
end
return 'OK'
"""


class Storage:
    def __init__(self, args):
        self.args = args
        self.tag = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(5)
        self.sock.connect((args.host, args.port))

    def redis(self, *args):
        result = subprocess.run(
            ['redis-cli', '-h', self.args.redis_host, '-p',
             str(self.args.redis_port), '--raw', *map(str, args)],
            capture_output=True, text=True, check=True, timeout=5)
        return result.stdout.strip()

    def update(self, digest, command, flag, value=1):
        self.tag += 1
        # v4, no shingles/extensions; ACK each request before sending the next
        # so input order is known, independent of UDP delivery scheduling.
        packet = struct.pack('<BBBBiI64s', 4, command, 0, flag,
                             value, self.tag, digest)
        self.sock.send(packet)
        reply = self.sock.recv(4096)
        value, _, tag, probability = struct.unpack('<iIIf', reply[:16])
        assert tag == self.tag, f'unexpected reply tag: {tag}, wanted {self.tag}'
        assert value == 0 and probability == 1.0, f'update rejected: {reply.hex()}'

    def sync(self):
        before = int(self.redis('GET', 'fuzzylocal') or 0)
        result = subprocess.run(
            [self.args.rspamadm, 'control', '-s', self.args.control, 'fuzzy_sync'],
            capture_output=True, text=True, check=True, timeout=5)
        # Control only acknowledges dispatch. Wait for the version INCR, which
        # happens after every update in the batch has completed.
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if int(self.redis('GET', 'fuzzylocal') or 0) == before + 1:
                return
            time.sleep(0.02)
        raise AssertionError(f'fuzzy sync did not finish: {result.stdout} {result.stderr}')

    def verify(self, digests, flag, weight=1):
        keys = ['fuzzy' + digest.decode('ascii') for digest in digests]
        result = self.redis('EVAL', VERIFY, len(keys), *keys, flag, weight)
        assert result == 'OK', result

    def run(self):
        digests = [hashlib.sha256(f'{self.args.case}:{i}'.encode()).hexdigest().encode()
                   for i in range(128)]
        if self.args.case == 'duplicates':
            # Exercise the real C deduplication: same digest/flag ADD weights
            # merge, while each distinct digest must still be written.
            for _ in range(20):
                for digest in digests:
                    self.update(digest, 1, 50)
            self.sync()
            self.verify(digests, 50, 20)
            return

        for digest in digests:
            self.update(digest, 1, 50)
        self.sync()
        self.verify(digests, 50)

        for _ in range(5):
            for digest in digests:
                if self.args.case == 'delete-add':
                    # Different flags deliberately survive C deduplication,
                    # reproducing Mailcow's ham-delete/spam-add sequence.
                    self.update(digest, 2, 51)
                    self.update(digest, 1, 50)
                else:
                    self.update(digest, 1, 51)
                    self.update(digest, 2, 50)
            self.sync()
            self.verify(digests, 50 if self.args.case == 'delete-add' else 'deleted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', required=True, type=int)
    parser.add_argument('--redis-host', required=True)
    parser.add_argument('--redis-port', required=True, type=int)
    parser.add_argument('--rspamadm', required=True)
    parser.add_argument('--control', required=True)
    parser.add_argument('--case', required=True,
                        choices=('delete-add', 'add-delete', 'duplicates'))
    storage = Storage(parser.parse_args())
    try:
        storage.run()
    finally:
        storage.sock.close()
    print(f'{storage.args.case}: real Redis state verified')


if __name__ == '__main__':
    main()
