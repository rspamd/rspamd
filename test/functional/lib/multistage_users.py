"""DATA policy selection and real ASN/multimap producer replay."""
import copy
import json
import time

from multistage import Milter, _http, _seal
from rspamd import _build_multipart, _parse_multipart_response


def _metadata(ip='192.0.2.1', helo='mail.example.com', recipients=None, **kwargs):
    return dict(ip=ip, helo=helo, **{'from': '<sender@example.com>',
                'rcpt': recipients or ['<recipient@example.org>']}, **kwargs)


def _checkpoint(host, port, metadata=None):
    metadata = metadata or _metadata()
    request = dict(version=1, issued=time.time(), id='d' * 32, metadata=metadata)
    code, body, _ = _http(host, port, '/checkdata', _seal('data-request', request))
    assert code == 200, (code, body)
    return metadata, json.loads(body[129:])


def _headers(extra=()):
    return [('From', 'sender@example.com'), ('To', 'recipient@example.org'),
            ('Subject', 'test'),
            ('Received', 'from source.example.org (source.example.org [192.0.2.2]) '
             'by mx.example.org; Sun, 13 Sep 2026 10:00:00 +0000')] + list(extra)


def _resume(host, port, metadata, response=None, extra=()):
    meta = dict(metadata)
    if response is not None:
        meta['early_record'] = _seal('data-response', response).decode()
    boundary = 'rspamd-users-replay-test'
    message = ''.join(name + ': ' + value + '\r\n' for name, value in _headers(extra)).encode()
    code, body, content_type = _http(host, port, '/checkv3',
        _build_multipart(boundary, json.dumps(meta), message + b'\r\nMessage body.\r\n'),
        {'Content-Type': 'multipart/form-data; boundary=' + boundary})
    assert code == 200, (code, body)
    result = json.loads(_parse_multipart_response(body, content_type))
    state = result.get('milter', {}).get('add_headers', {}).get('X-User-Test')
    return (json.loads(state['value'] if isinstance(state, dict) else state) if state else None), result


def _milter(host, port, checkpoint=True, recipients=('recipient@example.org',),
            ip='192.0.2.1', helo='mail.example.com', user=None, extra=()):
    client = Milter(host, port, ip, helo)
    try:
        if user:
            client.send(b'D', b'M{auth_authen}\0' + user.encode() + b'\0')
        client.send(b'M', b'<sender@example.com>\0')
        for recipient in recipients:
            client.send(b'R', ('<' + recipient + '>\0').encode())
        if checkpoint:
            decision = client.data()
            if decision != b'c':
                return decision, None
        command, added = client.finish_message(_headers(extra))
        assert command in (b'a', b'c'), (command, added)
        return b'c', json.loads(added['X-User-Test'])
    finally:
        client.close()


def multistage_users_policies(host, port):
    for options, expected in [
        ({'recipients': ['blocked@protected.test']}, b'r'),
        ({'recipients': ['exempt@protected.test']}, b'c'),
        ({'recipients': ['exempt@protected.test', 'blocked@protected.test']}, b'r'),
        ({'recipients': ['blocked@protected.test', 'exempt@protected.test']}, b'r'),
        ({'recipients': ['blocked@protected.test'], 'user': 'trusted'}, b'c'),
        ({'recipients': ['blocked@protected.test'], 'user': 'untrusted'}, b'r'),
        ({'recipients': ['blocked@protected.test'], 'extra': [('X-EOM-Exempt', 'yes')]}, b'r'),
        ({'recipients': ['blocked@protected.test'], 'ip': '192.0.2.2'}, b'c'),
        ({'recipients': ['blocked@protected.test'], 'ip': '192.0.2.2', 'helo': 'bad.example.com'}, b'r'),
        ({'recipients': ['helo-exempt@protected.test'], 'ip': '192.0.2.2', 'helo': 'bad.example.com'}, b'c'),
        ({'recipients': ['helo-exempt@protected.test'], 'helo': 'bad.example.com'}, b'r'),
    ]:
        decision, _ = _milter(host, port, **options)
        assert decision == expected, (options, decision, expected)


def multistage_users_parity(host, port):
    for options in ({}, {'ip': '2001:db8::1'}, {'ip': '192.0.2.3'},
                    {'ip': '192.0.2.4'}, {'helo': 'bad.example.com'},
                    {'extra': [('X-Change-IP', 'yes')]},
                    {'extra': [('X-EOM-Exempt', 'yes')]}):
        _, full = _milter(host, port, checkpoint=False, **options)
        _, replayed = _milter(host, port, **options)
        # Facts are checkpoint bookkeeping; EOM state and results must agree.
        for field in ('asn', 'country', 'ipnet', 'symbols'):
            assert replayed[field] == full[field], (options, field, replayed, full)
        if options == {}:
            assert replayed['asn'] == '64501', replayed
            assert {'USER_ASN', 'USER_ASN_SELECTOR', 'USER_COUNTRY', 'USER_SMTP',
                    'USER_MIME', 'USER_HEADER'} <= replayed['symbols'].keys(), replayed
        if 'extra' in options and options['extra'][0][0] == 'X-Change-IP':
            assert replayed['asn'] == '64502' and 'USER_ASN' not in replayed['symbols'], replayed
        if 'extra' in options and options['extra'][0][0] == 'X-EOM-Exempt':
            assert 'USER_ASN' not in replayed['symbols'], replayed


def multistage_users_record(host, port):
    metadata, response = _checkpoint(host, port)
    assert response['decision'] == 'continue', response
    checks = response['record']['checks']
    assert {'ASN_CHECK', 'USER_ASN', 'USER_COUNTRY', 'USER_ASN_SELECTOR', 'USER_SMTP',
            'USER_HELO'} <= checks.keys(), checks
    assert not {'USER_MIME', 'USER_HEADER', 'USER_CHANGE_IP', 'SETTINGS_CHECK',
                'SETTINGS_APPLY'} & checks.keys(), checks
    assert checks['ASN_CHECK']['facts']['asn']['asn'] == '64501', checks
    full, _ = _resume(host, port, metadata)
    replayed, _ = _resume(host, port, metadata, response)
    assert replayed['asn'] == full['asn'] == '64501', (replayed, full)
    assert replayed['symbols'] == full['symbols'], (replayed, full)
    assert replayed['dns'] < full['dns'], (replayed, full)


def multistage_users_invalid_facts(host, port):
    metadata, response = _checkpoint(host, port)
    full, _ = _resume(host, port, metadata)
    for key, value in [('ip', '192.0.2.2'), ('status', 'error'), ('status', 'pending'),
                       ('asn', []), ('country', 42), ('provider', 'other.test')]:
        bad = copy.deepcopy(response)
        bad['record']['checks']['ASN_CHECK']['facts']['asn'][key] = value
        state, _ = _resume(host, port, metadata, bad)
        assert state['asn'] == '64501' and state['symbols'] == full['symbols'], (key, state)
        assert state['dns'] == full['dns'], (key, state, full)
    for key, value in [('digest', 'changed'), ('value', '64502')]:
        bad = copy.deepcopy(response)
        check = bad['record']['checks']['USER_ASN']
        check['facts']['map'][key] = value
        # A stale producer result must not be inserted, even if the MAC is valid.
        check['ops'] = []
        state, _ = _resume(host, port, metadata, bad)
        assert 'USER_ASN' in state['symbols'], (key, state)


def multistage_users_settings(host, port):
    metadata = _metadata(recipients=['<blocked@protected.test>'], settings_id='ordinary_disable')
    _, response = _checkpoint(host, port, metadata)
    assert response['decision'] == 'reject', response
    assert response['terminal']['policy_recipient'] == 'blocked@protected.test', response
    metadata['rcpt'] = ['<recipient@example.org>']
    _, response = _checkpoint(host, port, metadata)
    full, _ = _resume(host, port, metadata)
    replayed, _ = _resume(host, port, metadata, response)
    assert replayed['symbols'] == full['symbols'], (replayed, full)
    assert 'USER_ASN' not in replayed['symbols'], replayed


def multistage_users_action(host, port):
    metadata, response = _checkpoint(host, port, _metadata(helo='action.example.com'))
    assert response['decision'] == 'continue', response
    for record in (None, response):
        _, result = _resume(host, port, metadata, record)
        assert result['action'] == 'soft reject', result


def multistage_users_asn_outcomes(host, port):
    for ip, status in [('192.0.2.3', 'none'), ('192.0.2.4', 'error'), ('127.0.0.2', 'skip')]:
        metadata, response = _checkpoint(host, port, _metadata(ip=ip))
        facts = response['record']['checks']['ASN_CHECK']['facts']['asn']
        assert facts['status'] == status and facts['asn'] is False, (ip, facts)
        full, _ = _resume(host, port, metadata)
        replayed, _ = _resume(host, port, metadata, response)
        assert replayed['symbols'] == full['symbols'], (ip, replayed, full)
        assert replayed['dns'] == (full['dns'] if status != 'none' else 0), (ip, replayed, full)


def multistage_users_relay(host, port, scanner_port):
    metadata = _metadata(ip='192.0.2.10', recipients=['<blocked@protected.test>'])
    _, response = _checkpoint(host, scanner_port, metadata)
    assert response['decision'] == 'continue', response
    # Nothing portable ran, so the scanner continues without a record at all
    assert 'ASN_CHECK' not in response.get('record', {}).get('checks', {}), response
    for checkpoint in (False, True):
        decision, state = _milter(host, port, checkpoint=checkpoint, ip='192.0.2.10',
                                  recipients=['blocked@protected.test'])
        assert decision == b'c' and state['asn'] == '64502', state
        assert 'USER_ASN' not in state['symbols'], state
