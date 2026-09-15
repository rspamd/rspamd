"""Real SPF/DMARC parity over both proxy paths and authenticated scanner records."""
import json
import socketserver
import struct
import threading
import time

from multistage import Milter, _http, _seal
from rspamd import _build_multipart, _parse_multipart_response


def _scan(host, port, sender, ip, helo, checkpoint, change=None, user=None, extra_headers=()):
    client = Milter(host, port, ip, helo)
    try:
        if user:
            client.send(b'D', b'M{auth_authen}\0' + user.encode() + b'\0')
        client.send(b'M', ('<' + sender + '>\0').encode())
        client.send(b'R', b'<recipient@example.org>\0')
        if checkpoint:
            assert client.data() == b'c'
        domain = sender.split('@')[-1] if sender else helo
        headers = [('From', 'sender@' + domain), ('To', 'recipient@example.org')]
        if change:
            headers.append(('X-SPF-Test-Change', change))
        headers.extend(extra_headers)
        command, added = client.finish_message(headers)
        assert command in (b'a', b'c'), command
        assert 'X-SPF-Test' in added, added
        return json.loads(added['X-SPF-Test'])
    finally:
        client.close()


def multistage_spf_parity(host, port, domain, result, symbol, ip='192.0.2.1',
                          sender=None, helo='pass.example.com', change=None, resolves=0, user=None):
    if sender is None:
        sender = 'sender@' + domain
    full = _scan(host, port, sender, ip, helo, False, change, user)
    replayed = _scan(host, port, sender, ip, helo, True, change, user)
    assert replayed.pop('resolves') == int(resolves), replayed
    assert full.pop('resolves') == (0 if result == 'skipped' else 1), full
    assert replayed == full, (replayed, full)
    if result == 'skipped':
        assert replayed['result'] is False and replayed['dmarc_checks'] == 1, replayed
        assert not replayed['symbols'], replayed
    else:
        assert replayed['result'] == result, replayed
        assert symbol in replayed['symbols'], replayed
        assert replayed['dmarc_checks'] == 2, replayed
        if domain == 'pass.example.com' and result == 'pass':
            assert 'DMARC_POLICY_ALLOW' in replayed['symbols'], replayed


def multistage_spf_early_reject(host, port):
    client = Milter(host, port)
    try:
        client.send(b'M', b'<reject@fail.example.com>\0')
        client.send(b'R', b'<recipient@example.org>\0')
        assert client.data() == b'r'
    finally:
        client.close()


def _checkpoint(host, port, sender):
    request = dict(version=1, issued=time.time(), id='b' * 32,
                   metadata=dict(ip='192.0.2.1', helo='pass.example.com',
                                 **{'from': '<' + sender + '>', 'rcpt': ['<rcpt@example.org>']}))
    code, body, _ = _http(host, port, '/checkdata', _seal('data-request', request))
    assert code == 200, (code, body)
    response = json.loads(body[129:])
    return request['metadata'], response


def multistage_spf_record(host, port, sender='sender@pass.example.com', expected=True):
    _, response = _checkpoint(host, port, sender)
    checks = response.get('record', {}).get('checks', {})
    if expected:
        spf = checks['SPF_CHECK']
        assert spf['facts']['spf']['result'] == 'pass', spf
        assert spf['facts']['spf']['record'].startswith('v=spf1 '), spf
        assert spf['ops'][0]['symbol'] == 'R_SPF_ALLOW', spf
    else:
        assert 'SPF_CHECK' not in checks, checks


def multistage_spf_invalid_facts(host, port):
    metadata, response = _checkpoint(host, port, 'sender@pass.example.com')
    saved = response['record']['checks']['SPF_CHECK']['facts']['spf']
    for key, value in [('result', 'invalid'), ('result', 1), ('record', []),
                       ('record', 'embedded\0nul'), ('skip', None), ('sender', False)]:
        bad = json.loads(json.dumps(response))
        bad['record']['checks']['SPF_CHECK']['facts']['spf'][key] = value
        meta = dict(metadata, early_record=_seal('data-response', bad).decode())
        boundary = 'rspamd-spf-replay-test'
        message = b'From: sender@pass.example.com\r\nTo: rcpt@example.org\r\n\r\nReal body\r\n'
        code, body, content_type = _http(host, port, '/checkv3',
            _build_multipart(boundary, json.dumps(meta), message),
            {'Content-Type': 'multipart/form-data; boundary=' + boundary})
        assert code == 200, (code, body)
        result = json.loads(_parse_multipart_response(body, content_type))
        state = result['milter']['add_headers']['X-SPF-Test']
        # The protocol can encode a single header directly or as an ordered object.
        if isinstance(state, dict):
            state = state['value']
        state = json.loads(state)
        assert state['resolves'] == 1 and state['dmarc_checks'] == 2, (key, state)
        assert state['facts'] == saved, (key, state)
        assert state['result'] == 'pass' and state['record'] == saved['record'], (key, state)


def _relay_headers():
    return [
        ('Received', 'from relay.example.com (relay.example.com [192.0.2.10]) by mx.example.com; Sun, 13 Sep 2026 10:00:00 +0000'),
        ('Received', 'from origin.example.com (origin.example.com [192.0.2.1]) by relay.example.com; Sun, 13 Sep 2026 09:59:59 +0000'),
    ]


def multistage_spf_external_relay(host, port):
    for checkpoint in (False, True):
        result = _scan(host, port, 'sender@pass.example.com', '192.0.2.2', 'pass.example.com',
                       checkpoint, extra_headers=_relay_headers())
        assert result['resolves'] == 1 and result['facts'] is False, result
        assert result['result'] == 'pass' and result['dmarc_checks'] == 2, result
        assert 'DMARC_POLICY_ALLOW' in result['symbols'], result


def multistage_spf_relay_plugin(host, port):
    for checkpoint in (False, True):
        # The relay's IP fails SPF and would trigger the early rejection policy.
        # Only Received headers reveal the authorized sender behind it.
        result = _scan(host, port, 'reject@pass.example.com', '192.0.2.2', 'pass.example.com',
                       checkpoint, extra_headers=_relay_headers())
        assert result['resolves'] == 1, result
        assert result['facts']['ip'] == '192.0.2.1', result
        assert result['facts']['helo'] == 'origin.example.com', result
        assert result['result'] == 'pass' and result['dmarc_checks'] == 2, result
        assert 'DMARC_POLICY_ALLOW' in result['symbols'], result


def multistage_spf_cached(host, port, dns_port):
    # Configured fake DNS replies deliberately have TTL=0, so use a real UDP
    # reply with a positive TTL to exercise the SPF LRU and count DNS queries.
    requests = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, sock = self.request
            pos, labels = 12, []
            while packet[pos]:
                length = packet[pos]
                labels.append(packet[pos + 1:pos + 1 + length])
                pos += length + 1
            end = pos + 5
            assert b'.'.join(labels) == b'cached.example.com'
            assert struct.unpack('!HH', packet[pos + 1:end]) == (16, 1)
            requests.append(packet)
            txt = b'v=spf1 ip4:192.0.2.1 -all'
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 16, 1, 600, len(txt) + 1)
            header = packet[:2] + struct.pack('!HHHHH', 0x8180, 1, 1, 0, 0)
            sock.sendto(header + packet[12:end] + answer + bytes([len(txt)]) + txt, self.client_address)

    server = socketserver.UDPServer((host, int(dns_port)), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        _scan(host, port, 'sender@cached.example.com', '192.0.2.1', 'pass.example.com', False)
        full = _scan(host, port, 'sender@cached.example.com', '192.0.2.1', 'pass.example.com', False)
        replayed = _scan(host, port, 'sender@cached.example.com', '192.0.2.1', 'pass.example.com', True)
        assert full.pop('resolves') == 1 and replayed.pop('resolves') == 0
        assert full == replayed, (full, replayed)
        assert replayed['record'].startswith('v=spf1 '), replayed
        assert replayed['symbols']['R_SPF_ALLOW']['options'] == ['+ip4:192.0.2.1:c'], replayed
        assert len(requests) == 1, len(requests)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
