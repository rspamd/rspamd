"""Real Postfix DATA/EOM integration. Run only in the disposable Docker image."""
import concurrent.futures
import email
import grp
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import smtplib
import socket
import subprocess
import threading
import time


WORK = Path('/tmp/postfix-data')
EVENTS = WORK / 'events.jsonl'
RESULTS = []
QUEUED = set()


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT)


def wait_port(port, process):
    until = time.monotonic() + 20
    while time.monotonic() < until:
        if process.poll() is not None:
            raise RuntimeError(f'process exited: {process.returncode}')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise RuntimeError(f'port {port} did not open')


class UnavailableCheckpoint(http.server.BaseHTTPRequestHandler):
    """Fail DATA transport; forward the actual EOM scan to the real scanner."""

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        if self.path == '/checkdata':
            status, data, content_type = 503, b'unavailable', 'text/plain'
        else:
            conn = http.client.HTTPConnection('127.0.0.1', 11333, timeout=5)
            try:
                headers = {k: v for k, v in self.headers.items()
                           if k.lower() not in ('host', 'connection')}
                conn.request('POST', self.path, body, headers)
                response = conn.getresponse()
                status, data = response.status, response.read()
                content_type = response.getheader('Content-Type', 'application/json')
            finally:
                conn.close()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def connect(port, ip='127.0.0.1', helo='pass.example.test'):
    smtp = smtplib.SMTP('127.0.0.1', port, timeout=8, source_address=(ip, 0))
    assert smtp.ehlo(helo)[0] == 250
    return smtp


def events_for(sender):
    rows = (json.loads(line) for line in EVENTS.read_text().splitlines())
    return [row for row in rows if row['from'] == sender]


def message(label, reject=False):
    headers = [('From', 'sender@example.test'), ('To', 'bob@localhost'),
               ('Subject', label), ('Message-ID', f'<{label}@example.test>')]
    if reject:
        headers.append(('X-Reject-EOM', 'yes'))
    return (''.join(f'{name}: {value}\r\n' for name, value in headers) +
            '\r\nA real body that must never be sent for an early rejection.\r\n').encode()


def check_eom(label, sender, code, response, expected=250, replayed=True,
              symbols=('R_SPF_ALLOW',)):
    assert code == expected, (label, code, response)
    rows = events_for(sender)
    assert len(rows) == 1 and rows[0]['terminal'] is False, (label, rows)
    state = rows[0]
    assert 'INTEGRATION_BODY' in state['symbols'], (label, state)
    assert state['spf_calls'] == (0 if replayed else 1), (label, state)
    assert state['dns'] == (0 if replayed else 2), (label, state)

    for symbol in symbols:
        assert symbol in state['symbols'], (label, symbol, state)
        assert len(state['symbols'][symbol]) <= 1, (label, symbol, state)

    if expected == 250:
        match = re.search(rb'queued as ([A-Za-z0-9]+)', response)
        assert match, response
        queue_id = match[1].decode()
        queued = email.message_from_string(run('postcat', '-qbh', queue_id))
        observed = queued.get('X-Multistage-Integration')
        assert observed and json.loads(observed) == state, (label, queued)
        QUEUED.add(queue_id)

    RESULTS.append(label)
    print('PASS', label, f'EOM={code}', 'replayed' if replayed else 'full-scan', flush=True)


def finish(smtp, label, sender, expected=250, replayed=True, symbols=('R_SPF_ALLOW',)):
    raw = message(label, reject=expected != 250)
    smtp.send(re.sub(br'(?m)^\.', b'..', raw) + b'.\r\n')
    code, response = smtp.getreply()
    check_eom(label, sender, code, response, expected, replayed, symbols)


def submit(smtp, label, domain='pass.example.test', recipients=('bob@localhost',),
           early=354, policy=None, eom=250, replayed=True, symbols=('R_SPF_ALLOW',)):
    sender = f'{label}@{domain}'
    assert smtp.mail(sender)[0] == 250, label
    for recipient in recipients:
        assert smtp.rcpt(recipient)[0] == 250, (label, recipient)
    code, response = smtp.docmd('DATA')
    assert code == early, (label, code, response)
    if early != 354:
        # No headers, body or terminating dot have been sent.
        rows = events_for(sender)
        assert len(rows) == 1, (label, rows)
        terminal = rows[0]['terminal']
        assert terminal['policy'] == policy and terminal['has_body'] is False, (label, rows)
        enhanced = b'5.7.1' if early == 554 else b'4.7.1'
        assert response == enhanced + b' ' + terminal['reason'].encode(), (label, response)
        assert 'INTEGRATION_BODY' not in rows[0]['symbols'], rows
        assert smtp.rset()[0] == 250, label
        RESULTS.append(label)
        print('PASS', label, f'DATA={code}', 'body-bytes-sent=0', flush=True)
    else:
        finish(smtp, label, sender, eom, replayed, symbols)


def pipelined(smtp, label):
    sender = f'{label}@pass.example.test'
    smtp.send(f'MAIL FROM:<{sender}>\r\nRCPT TO:<bob@localhost>\r\nDATA\r\n'.encode())
    replies = [smtp.getreply()[0] for _ in range(3)]
    assert replies == [250, 250, 354], replies
    finish(smtp, label, sender)


def chunked(smtp, label, reject=False):
    assert smtp.has_extn('chunking')
    sender = f'{label}@pass.example.test'
    assert smtp.mail(sender)[0] == 250
    assert smtp.rcpt('bob@localhost')[0] == 250
    raw = message(label)
    first, last = raw[:40], raw[40:]
    smtp.send(f'BDAT {len(first)}\r\n'.encode() + first)
    code, response = smtp.getreply()
    if reject:
        assert code == 554, (label, code, response)
        assert response == b'5.7.1 Blocked HELO', response
        rows = events_for(sender)
        assert len(rows) == 1 and rows[0]['terminal']['policy'] == 'helo', rows
        assert smtp.rset()[0] == 250
        RESULTS.append(label)
        print('PASS', label, f'BDAT={code}', f'first-chunk-bytes={len(first)}', flush=True)
        return
    assert code == 250, (label, code, response)
    smtp.send(f'BDAT {len(last)} LAST\r\n'.encode() + last)
    code, response = smtp.getreply()
    check_eom(label, sender, code, response)


def mode_cases(mode, port):
    with connect(port) as smtp:
        submit(smtp, mode + '-clean')
        submit(smtp, mode + '-spf', domain='fail.example.test', early=554, policy='spf')
        submit(smtp, mode + '-after-reject')
        submit(smtp, mode + '-temporary', domain='error.example.test', early=451, policy='spf-temporary')
        submit(smtp, mode + '-after-tempfail')
        submit(smtp, 'observer-slow-' + mode, domain='fail.example.test', early=554, policy='spf')
        submit(smtp, 'observer-error-' + mode, domain='fail.example.test', early=554, policy='spf')
        submit(smtp, mode + '-softfail', domain='soft.example.test', symbols=('R_SPF_SOFTFAIL',))
        submit(smtp, mode + '-spf-exempt', domain='fail.example.test',
               recipients=('exempt@localhost',), symbols=('R_SPF_FAIL',))
        for n, recipients in enumerate((('exempt@localhost', 'bob@localhost'),
                                         ('bob@localhost', 'exempt@localhost'))):
            submit(smtp, f'{mode}-mixed-{n}', domain='fail.example.test',
                   recipients=recipients, early=554, policy='spf')
        assert smtp.mail('abort@pass.example.test')[0] == 250
        assert smtp.rcpt('bob@localhost')[0] == 250
        assert smtp.rset()[0] == 250
        submit(smtp, mode + '-after-rset')
        submit(smtp, mode + '-body-reject', eom=554)
        submit(smtp, 'slow-' + mode, replayed=False)
        pipelined(smtp, mode + '-pipeline')
        chunked(smtp, mode + '-chunks')
    with connect(port, helo='blocked.example.test') as smtp:
        submit(smtp, mode + '-helo', early=554, policy='helo')
        submit(smtp, mode + '-helo-exempt', recipients=('exempt@localhost',),
               symbols=('R_SPF_ALLOW', 'INTEGRATION_HELO'))
        chunked(smtp, mode + '-chunk-reject', reject=True)
        assert smtp.ehlo('pass.example.test')[0] == 250
        submit(smtp, mode + '-after-helo')
    with connect(port, ip='127.0.0.2') as smtp:
        submit(smtp, mode + '-rbl', early=554, policy='rbl')
        submit(smtp, mode + '-rbl-exempt', recipients=('exempt@localhost',),
               symbols=('R_SPF_ALLOW', 'INTEGRATION_RBL'))
    def concurrent_case(n):
        with connect(port) as smtp:
            submit(smtp, f'{mode}-concurrent-{n}')
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(concurrent_case, range(3)))


def main():
    if not Path('/.dockerenv').exists():
        raise RuntimeError('Run only inside the disposable Postfix DATA image')
    transport = os.environ.get('MILTER_TRANSPORT', 'tcp')
    assert transport in ('tcp', 'unix')
    WORK.mkdir()
    EVENTS.touch()
    for setting in [
        'myhostname=postfix.example.test', 'mydestination=localhost',
        'inet_interfaces=127.0.0.1', 'inet_protocols=ipv4', 'local_recipient_maps=',
        'mynetworks=127.0.0.0/8', 'smtpd_relay_restrictions=permit_mynetworks,reject',
        'milter_protocol=6', 'milter_default_action=tempfail',
        'milter_command_timeout=5s', 'milter_content_timeout=5s',
        'defer_transports=smtp,local,relay', 'maillog_file=/dev/stdout',
        'smtpd_delay_reject=no', 'smtpd_tls_security_level=none',
    ]:
        run('postconf', '-e', setting)
    for port, mode, milter_port in ((2525, 'self', 11332), (2526, 'remote', 11336),
                                     (2527, 'fallback', 11338)):
        endpoint = (f'inet:127.0.0.1:{milter_port}' if transport == 'tcp' else
                    f'unix:/var/spool/postfix/rspamd-{mode}.sock')
        run('postconf', '-M', f'{port}/inet={port} inet n - n - - smtpd')
        run('postconf', '-P', f'{port}/inet/smtpd_milters={endpoint}')
    run('postfix', 'check')
    print('POSTFIX', run('postconf', 'mail_version').strip(), 'transport=' + transport, flush=True)
    print('RSPAMD', run('/opt/rspamd/bin/rspamd', '--version').strip(), flush=True)
    forwarding = http.server.ThreadingHTTPServer(('127.0.0.1', 18080), UnavailableCheckpoint)
    threading.Thread(target=forwarding.serve_forever, daemon=True).start()
    rspamd = postfix = None
    try:
        with (WORK / 'rspamd.stdout').open('w') as log:
            rspamd = subprocess.Popen([
                '/opt/rspamd/bin/rspamd', '-f', '--insecure',
                '--var=DBDIR=/tmp/postfix-data', '-c', '/opt/postfix-data/rspamd.conf',
            ], stdout=log, stderr=subprocess.STDOUT)
        for port in (11332, 11333, 11336, 11338):
            wait_port(port, rspamd)
        for mode in ('self', 'remote', 'fallback'):
            path = f'/var/spool/postfix/rspamd-{mode}.sock'
            os.chown(path, -1, grp.getgrnam('postfix').gr_gid)
            os.chmod(path, 0o660)
        with (WORK / 'postfix.log').open('w') as log:
            postfix = subprocess.Popen(['postfix', 'start-fg'], stdout=log, stderr=subprocess.STDOUT)
        for port in (2525, 2526, 2527):
            wait_port(port, postfix)
        mode_cases('self', 2525)
        mode_cases('remote', 2526)
        with connect(2527) as smtp:
            submit(smtp, 'transport-fallback', replayed=False)
        queue = [json.loads(line)['queue_id'] for line in run('postqueue', '-j').splitlines()]
        assert set(queue) == QUEUED, (queue, QUEUED)
        print('PASS queue-contains-only-accepted-messages', len(queue), flush=True)
        print('PASS', len(RESULTS), 'SMTP transactions', transport, flush=True)
    except Exception:
        for name in ('rspamd.stdout', 'rspamd.log', 'postfix.log'):
            path = WORK / name
            if path.exists():
                print(name, path.read_text()[-18000:], flush=True)
        raise
    finally:
        for process in (postfix, rspamd):
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        forwarding.shutdown()
        forwarding.server_close()


if __name__ == '__main__':
    main()
