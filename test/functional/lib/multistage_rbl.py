"""Mixed RBL rules over DATA/EOM with real, counted DNS replies."""
import copy
import ipaddress
import json
import socketserver
import struct
import threading
import time
from collections import Counter

from multistage import Milter, _http, _seal
from rspamd import _build_multipart, _parse_multipart_response

_server = None
_thread = None
_requests = Counter()


def start_rbl_dns(host, port):
    global _server, _thread

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, sock = self.request
            pos, labels = 12, []
            while packet[pos]:
                length = packet[pos]
                labels.append(packet[pos + 1:pos + 1 + length].decode())
                pos += length + 1
            end = pos + 5
            name = '.'.join(labels)
            qtype, qclass = struct.unpack('!HH', packet[pos + 1:end])
            _requests[name] += 1
            hit = name.endswith('.rbl.test')
            if name.endswith('.miss.rbl.test'):
                hit = False
            if name.endswith('.white.rbl.test'):
                ipv6 = ipaddress.ip_address('2001:db8::3').reverse_pointer.removesuffix('ip6.arpa')
                hit = name.startswith(('3.2.0.192.', '9.9.9.9.', ipv6))
            address = b'\x7f\0\0\x02'
            if name in ('shared.example.com', 'mail.example.com'):
                hit = True
                address = b'\xc0\0\x02\x01'
            hit = hit and qtype == 1 and qclass == 1
            header = packet[:2] + struct.pack('!HHHHH', 0x8180 if hit else 0x8183,
                                            1, int(hit), 0, 0)
            answer = b''
            if hit:
                answer = b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + address
            sock.sendto(header + packet[12:end] + answer, self.client_address)

    _server = socketserver.UDPServer((host, int(port)), Handler)
    _thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _thread.start()


def stop_rbl_dns():
    if _server:
        _server.shutdown()
        _server.server_close()
        _thread.join(timeout=5)


def _headers(change=None, required=False, received='8.8.8.8'):
    headers = [('From', 'sender@example.com'), ('To', 'recipient@example.org'),
               ('Subject', 'shared.example.com'),
               ('Received', 'from source.example.org (source.example.org [' + received +
                ']) by mx.example.org; Sun, 13 Sep 2026 10:00:00 +0000')]
    if change:
        headers.append(('X-RBL-Change', change))
    if required:
        headers.append(('X-RBL-Required', 'yes'))
    return headers


BODY = b'Visit http://shared.example.com/path for details.\r\n'


def _scan(host, port, checkpoint, ip='192.0.2.1', change=None, required=False,
          received='8.8.8.8', user=None, extra_headers=()):
    _requests.clear()
    client = Milter(host, port, ip, 'shared.example.com')
    try:
        if user:
            client.send(b'D', b'M{auth_authen}\0' + user.encode() + b'\0')
        client.envelope()
        early = {}
        if checkpoint:
            assert client.data() == b'c'
            early = dict(_requests)
        command, added = client.finish_message(_headers(change, required, received) + list(extra_headers), BODY)
        assert command in (b'a', b'c'), (command, added)
        state = json.loads(added['X-RBL-Test'])
        for symbol in state['symbols'].values():
            symbol['options'] = sorted(symbol.get('options') or [])
        return state, early, dict(_requests)
    finally:
        client.close()


def multistage_rbl_parity(host, port):
    for options in ({}, {'ip': '192.0.2.3'}, {'ip': '2001:db8::1'}, {'ip': '2001:db8::3'},
                    {'received': '9.9.9.9'}, {'required': True},
                    {'change': 'ip'}, {'change': 'white'}, {'change': 'disable'},
                    {'user': 'authenticated'}):
        full, _, full_queries = _scan(host, port, False, **options)
        replayed, early, queries = _scan(host, port, True, **options)
        assert replayed == full, (options, replayed, full)
        assert 'RBL_NEGATIVE' not in replayed['symbols'], replayed
        assert not any('.scripted.' in name or '.required.' in name for name in early), early
        assert 'shared.example.com.selected.rbl.test' not in early, early
        assert '8.8.8.8.mixed.rbl.test' not in early, early
        assert early.get('shared.example.com.mixed.rbl.test') == 1, early
        if 'change' not in options:
            assert queries == full_queries, (options, queries, full_queries)
            assert queries['shared.example.com.mixed.rbl.test'] == 1, queries
        if options == {}:
            assert replayed['symbols']['RBL_MIXED_HIT']['options'] == [
                '192.0.2.1:from', '8.8.8.8:received',
                'shared.example.com:helo', 'shared.example.com:url'], replayed
            assert 'RBL_REQUIRED' not in replayed['symbols'], replayed
        if options.get('required'):
            assert 'RBL_REQUIRED' in replayed['symbols'], replayed
        if options.get('ip') == '192.0.2.3' or options.get('change') == 'white':
            assert '192.0.2.3:from' not in replayed['symbols']['RBL_MIXED_HIT']['options'], replayed
            assert '192.0.2.3:from' in replayed['symbols']['RBL_WHITE_HIT']['options'], replayed
        if options.get('ip') == '2001:db8::3':
            assert '2001:db8::3:from' not in replayed['symbols']['RBL_MIXED_HIT']['options'], replayed
            assert '2001:db8::3:from' in replayed['symbols']['RBL_WHITE_HIT']['options'], replayed
        if options.get('change') == 'disable':
            assert 'RBL_MIXED_HIT' not in replayed['symbols'], replayed


def _checkpoint(host, port, metadata=None):
    metadata = metadata or dict(ip='192.0.2.1', helo='shared.example.com',
                               **{'from': '<sender@example.com>', 'rcpt': ['<rcpt@example.org>']})
    request = dict(version=1, issued=time.time(), id='c' * 32, metadata=metadata)
    code, body, _ = _http(host, port, '/checkdata', _seal('data-request', request))
    assert code == 200, (code, body)
    return metadata, json.loads(body[129:])


def multistage_rbl_record(host, port):
    _, response = _checkpoint(host, port)
    checks = response['record']['checks']
    assert 'RBL_MIXED_ENVELOPE' in checks, checks
    assert 'RBL_WHITE_ENVELOPE' in checks, checks
    assert 'RBL_SELECTED_ENVELOPE' in checks, checks
    assert checks['RBL_MAPPED_ENVELOPE']['facts']['plan']['matchers']['RBL_MAPPED_HIT'], checks
    assert not any(name.endswith('_MESSAGE') for name in checks), checks
    assert 'RBL_SCRIPTED_ENVELOPE' not in checks and 'RBL_REQUIRED_ENVELOPE' not in checks, checks
    mixed = checks['RBL_MIXED_ENVELOPE']
    assert mixed['facts']['complete'] is True, mixed
    assert len([op for op in mixed['ops'] if 'symbol' in op]) == 2, mixed
    assert set(mixed['facts']['answers']) == {
        '1.2.0.192.mixed.rbl.test', 'shared.example.com.mixed.rbl.test'}, mixed


def _resume(host, port, metadata, response):
    meta = dict(metadata)
    if response is not None:
        meta['early_record'] = _seal('data-response', response).decode()
    boundary = 'rspamd-rbl-replay-test'
    message = ''.join(name + ': ' + value + '\r\n' for name, value in _headers()).encode()
    code, body, content_type = _http(host, port, '/checkv3',
        _build_multipart(boundary, json.dumps(meta), message + b'\r\n' + BODY),
        {'Content-Type': 'multipart/form-data; boundary=' + boundary})
    assert code == 200, (code, body)
    result = json.loads(_parse_multipart_response(body, content_type))
    state = result['milter']['add_headers']['X-RBL-Test']
    return json.loads(state['value'] if isinstance(state, dict) else state)


def multistage_rbl_settings(host, port):
    for settings_id in ('rbl_only_virtual', 'rbl_disable_public'):
        metadata = dict(ip='192.0.2.1', helo='shared.example.com', settings_id=settings_id,
                        **{'from': '<sender@example.com>', 'rcpt': ['<rcpt@example.org>']})
        _, response = _checkpoint(host, port, metadata)
        full = _resume(host, port, metadata, None)
        replayed = _resume(host, port, metadata, response)
        for state in (full, replayed):
            for symbol in state['symbols'].values():
                symbol['options'] = sorted(symbol.get('options') or [])
        assert full == replayed, (settings_id, full, replayed)
        if settings_id == 'rbl_only_virtual':
            assert set(replayed['symbols']) == {'RBL_MIXED_HIT'}, replayed
            assert len(replayed['symbols']['RBL_MIXED_HIT']['options']) == 4, replayed
        else:
            assert 'RBL_MIXED_HIT' not in replayed['symbols'], replayed


def multistage_rbl_invalid_facts(host, port):
    metadata, response = _checkpoint(host, port)
    changes = [('complete', False), ('plan', {}), ('answers', []),
               ('answers', {'bad': {'results': ['invalid IP'], 'error': False}})]
    for key, value in changes:
        bad = copy.deepcopy(response)
        bad['record']['checks']['RBL_MIXED_ENVELOPE']['facts'][key] = value
        _requests.clear()
        state = _resume(host, port, metadata, bad)
        assert _requests['1.2.0.192.mixed.rbl.test'] == 1, (key, _requests)
        assert state['symbols']['RBL_MIXED_HIT']['options'].count('192.0.2.1:from') == 1, state

    bad = copy.deepcopy(response)
    bad['record']['checks']['RBL_MAPPED_ENVELOPE']['facts']['plan']['matchers']['RBL_MAPPED_HIT'] = 'changed'
    _requests.clear()
    state = _resume(host, port, metadata, bad)
    assert _requests['shared.example.com.mapped.rbl.test'] == 1, _requests
    assert sorted(state['symbols']['RBL_MAPPED_HIT']['options']) == [
        'shared.example.com:helo', 'shared.example.com:url'], state


def multistage_rbl_early_reject(host, port):
    client = Milter(host, port, '192.0.2.1', 'shared.example.com')
    try:
        client.envelope('reject')
        assert client.data() == b'r'
    finally:
        client.close()


def multistage_rbl_relay(host, port):
    for checkpoint in (False, True):
        state, early, _ = _scan(host, port, checkpoint, ip='192.0.2.10')
        assert not early, early
        assert '8.8.8.8:from' in state['symbols']['RBL_MIXED_HIT']['options'], state
        assert not any('192.0.2.10' in opt for sym in state['symbols'].values()
                       for opt in sym['options']), state


def multistage_rbl_selector_white(host, port):
    for checkpoint in (False, True):
        state, early, _ = _scan(host, port, checkpoint,
                               extra_headers=[('X-RBL-White', '192.0.2.1')])
        assert not any('.mixed.' in name for name in early), early
        assert '192.0.2.1:from' not in state['symbols']['RBL_MIXED_HIT']['options'], state
        assert state['symbols']['RBL_SELECTOR_WHITE_HIT']['options'] == ['192.0.2.1:from'], state


def multistage_rbl_resolved(host, port):
    full, _, full_queries = _scan(host, port, False)
    replayed, early, queries = _scan(host, port, True)
    assert replayed == full, (replayed, full)
    name = '1.2.0.192.resolved.rbl.test'
    assert early[name] == 1 and queries[name] == 1 and full_queries[name] == 1, (early, queries, full_queries)
    assert replayed['symbols']['RBL_RESOLVED']['options'] == [
        '192.0.2.1:from', '192.0.2.1:mail.example.com:rdns',
        '192.0.2.1:shared.example.com:helo', '192.0.2.1:shared.example.com:url'], replayed
