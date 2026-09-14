"""Exercise real exporter plugins with Redis and an HTTP capture endpoint."""
import http.server
import json
import threading
import time
import urllib.parse

import msgpack
import redis

from multistage import Milter, _http, _seal

_collector = None
_thread = None
_rows = []
_failure_delay = 0


def start_export_collector(host, port):
    global _collector, _thread

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers['Content-Length']))
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get('query', [''])[0]
            code, reply = 200, b'{}'

            if self.path == '/failure':
                time.sleep(_failure_delay)
                code = 503
            elif query.startswith('INSERT INTO rspamd ('):
                fields = query.partition('(')[2].partition(')')[0].replace('`', '').split(',')

                for line in body.decode().splitlines():
                    values = line.split('\t')
                    assert len(fields) == len(values), (fields, values)
                    _rows.append(dict(zip(fields, values)))
            elif b'SELECT' in body:
                reply = b'{"v":13}\n'

            self.send_response(code)
            self.send_header('Content-Length', str(len(reply)))
            self.end_headers()
            try:
                self.wfile.write(reply)
            except (BrokenPipeError, ConnectionResetError):
                # The DATA deadline cancels the deliberately slow export.
                pass

    _collector = http.server.ThreadingHTTPServer((host, int(port)), Handler)
    _thread = threading.Thread(target=_collector.serve_forever, daemon=True)
    _thread.start()


def stop_export_collector():
    if _collector:
        _collector.shutdown()
        _collector.server_close()
        _thread.join(timeout=5)


def multistage_exports(host, port, redis_host, redis_port):
    client = redis.Redis(host=redis_host, port=int(redis_port))
    keys = {name: 'test:terminal:' + name for name in ('history', 'json', 'structured', 'raw', 'custom')}
    client.delete(*keys.values())
    before = len(_rows)
    milter = Milter(host, port)

    try:
        for count, sender in enumerate(('continue', 'reject', 'defer'), 1):
            milter.envelope(sender)
            decision = milter.data()

            if sender == 'continue':
                assert decision == b'c'
                assert all(client.llen(key) == 0 for key in keys.values())
                assert len(_rows) == before
                milter.eom('replayed')
            else:
                assert decision == (b'r' if sender == 'reject' else b't')

            until = time.monotonic() + 5

            while len(_rows) < before + count and time.monotonic() < until:
                time.sleep(.05)

            assert len(_rows) == before + count, _rows[before:]
            history = json.loads(client.lindex(keys['history'], 0))
            metadata = json.loads(client.lindex(keys['json'], -1))
            structured = msgpack.unpackb(client.lindex(keys['structured'], -1), raw=False)
            row = _rows[-1]

            for name in ('history', 'json', 'structured'):
                assert client.llen(keys[name]) == count, (name, count)

            assert client.llen(keys['raw']) == 1
            assert client.llen(keys['custom']) == 1

            if sender == 'continue':
                assert row['DecisionStage'] == 'eom', row
                assert row['HasBody'] == '1' and int(row['Size']) > 0, row
                assert row['HasMime'] == '1' and row['NUrls'] == '0', row
                continue

            action = 'reject' if sender == 'reject' else 'soft reject'

            for event in (history, metadata, structured):
                assert event['decision_stage'] == 'data' and event['action'] == action, event
                assert event['has_headers'] is False and event['has_body'] is False, event
                assert event['size'] is None and event['subject'] is None, event
                assert event['reply_delivered'] is None, event
                assert 'message' not in event and 'attachments' not in event, event
                assert event['event_id'] == metadata['event_id'], event

            assert 'DATA_PRODUCER' in history['symbols'], history
            assert row['DecisionStage'] == 'data' and row['Action'] == action, row
            assert row['EventId'] == metadata['event_id'], row
            assert row['Size'] == '0' and row['NUrls'] == '0', row
            assert row['HasBody'] == '0' and row['HasMime'] == '0', row
            assert row['Policy'] == metadata['policy'] and row['PolicyReason'] == metadata['reason'], row
            assert row['BodyHeader'] == 'unavailable' and row['ClientHelo'] == 'mail.example.com', row
            milter.send(b'A')

        time.sleep(.15)
        assert len(_rows) == before + 3, _rows[before:]
    finally:
        milter.close()
        client.close()


def multistage_export_failure(host, port, delay=0):
    global _failure_delay
    delay = float(delay)
    _failure_delay = delay
    request = dict(version=1, issued=time.time(), id='f' * 32,
                   metadata=dict(ip='192.0.2.1', helo='mail.example.com',
                                 **{'from': '<reject@example.com>', 'rcpt': ['<rcpt@example.org>']}))
    started = time.monotonic()
    try:
        status, body, _ = _http(host, port, '/checkdata', _seal('data-request', request))
    finally:
        _failure_delay = 0
    assert status == 200, (status, body)
    response = json.loads(body[129:])
    assert response['decision'] == 'reject', response
    assert response['terminal']['observer_status'] == ('timeout' if delay else 'error'), response
    if delay:
        assert time.monotonic() - started < float(delay), 'exporter delayed the frozen DATA reply'
