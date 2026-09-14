"""Real ClickHouse fresh-schema and populated v12 migration regression."""
import http.client
import json
from pathlib import Path
import socket
import sys
import subprocess
import time
import urllib.parse


def query(sql, database='default'):
    conn = http.client.HTTPConnection('127.0.0.1', 8123, timeout=10)
    conn.request('POST', '/?' + urllib.parse.urlencode({'database': database}), sql.encode())
    resp = conn.getresponse()
    body = resp.read().decode()
    assert resp.status == 200, (sql, resp.status, body)
    return body


def until(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.1)
    raise AssertionError('condition timed out')


def ready(port, proc):
    assert proc.poll() is None, proc.returncode
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=.1):
            return True
    except OSError:
        return False


sys.path.insert(0, '/source/test/functional/lib')
from multistage import Milter


def transaction(port, blocked):
    client = Milter('127.0.0.1', port, ip='127.0.0.1',
                    helo='blocked.example.test' if blocked else 'mail.example.test')
    try:
        client.send(b'M', b'<sender@pass.example.test>\0')
        client.send(b'R', b'<bob@localhost>\0')
        assert client.data() == (b'r' if blocked else b'c')
        if blocked:
            assert client.data_reply == b'554 5.7.1 Blocked HELO\0'
        else:
            result, _ = client.finish_message(headers=[('From', 'sender@pass.example.test'),
                                                       ('To', 'bob@localhost'),
                                                       ('Subject', 'Accepted message')])
            assert result in (b'a', b'c')
    finally:
        client.close()


if not Path('/.dockerenv').exists():
    raise RuntimeError('Run only inside the disposable integration image')

root = Path('/tmp/postfix-data')
root.mkdir(exist_ok=True)
base = Path('/opt/postfix-data/rspamd.conf').read_text()
Path('/opt/postfix-data/rules.lua').write_text(Path('/opt/postfix-data/rules.lua').read_text() +
    "\ndofile('/source/src/plugins/lua/clickhouse.lua')\n")
legacy = Path('/opt/postfix-data/schema12.sql').read_text()
print('ClickHouse', query('SELECT version()').strip(), flush=True)

for database in ('fresh', 'upgrade'):
    query('CREATE DATABASE ' + database)
    if database == 'upgrade':
        query(legacy, database)
        query('CREATE TABLE rspamd_version (Version UInt32) ENGINE = TinyLog', database)
        query('INSERT INTO rspamd_version VALUES (12)', database)
        query("INSERT INTO rspamd (Date,TS,Size,NUrls,MessageId) VALUES (today(),now(),42,0,'legacy')", database)
    conf = base + '''
clickhouse {
  servers = "127.0.0.1:8123";
  database = "%s";
  allow_local = true;
  use_gzip = false;
  enable_symbols = true;
  insert_subject = true;
  enable_digest = true;
  check_timeout = 0.1;
  limits { max_rows = 1; max_interval = 0.1; }
}
''' % database
    config = root / 'clickhouse-test.conf'
    config.write_text(conf)
    with (root / 'stdout').open('w') as output:
        proc = subprocess.Popen(['/opt/rspamd/bin/rspamd', '-f', '--insecure',
             '--var=DBDIR=/tmp/postfix-data', '-c', str(config)], stdout=output, stderr=subprocess.STDOUT)
    try:
        until(lambda: ready(11332, proc) and ready(11336, proc))
        until(lambda: query("SELECT count() FROM system.tables WHERE database='%s' AND name='rspamd_version'" % database).strip() == '1')
        until(lambda: query('SELECT max(Version) FROM rspamd_version', database).strip() == '13')
        columns = [json.loads(line) for line in query(
            "SELECT name,type FROM system.columns WHERE database='%s' AND table='rspamd' AND name IN ('Size','NUrls') FORMAT JSONEachRow" % database).splitlines()]
        assert {column['name']: column['type'] for column in columns} == {'Size': 'UInt32', 'NUrls': 'Int32'}, columns
        for port in (11332, 11336):
            transaction(port, True)
            transaction(port, False)
        expected = 5 if database == 'upgrade' else 4
        until(lambda: int(query('SELECT count() FROM rspamd', database)) == expected)
        time.sleep(.3)
        rows = [json.loads(line) for line in query('''SELECT DecisionStage,CompletionKind,EventId,Policy,PolicyReason,
            HasHeaders,HasBody,HasMime,Size,NUrls,MessageId,Subject,TaskUUID FROM rspamd FORMAT JSONEachRow''', database).splitlines()]
        early = [r for r in rows if r['DecisionStage'] == 'data']
        full = [r for r in rows if r['DecisionStage'] == 'eom']
        assert len(early) == 2 and len(rows) == expected, rows
        for r in early:
            assert r['Size'] == 0 and r['NUrls'] == 0, r
            assert r['HasHeaders'] == r['HasBody'] == r['HasMime'] == 0, r
            assert r['Policy'] == 'helo' and r['PolicyReason'] == 'Blocked HELO', r
            assert r['CompletionKind'] == 'early_reject' and r['EventId'], r
            assert not r['Subject'], r
        assert len({r['EventId'] for r in early}) == 2
        for r in full:
            assert r['HasBody'] == 1 and r['Size'] > 0 and r['NUrls'] == 0, r
            assert r['CompletionKind'] == 'full_scan', r
        if database == 'upgrade':
            assert next(r for r in full if r['MessageId'] == 'legacy')['Size'] == 42
        mean_size = float(query('SELECT avgIf(Size, HasBody = 1) FROM rspamd', database))
        assert mean_size == sum(row['Size'] for row in full) / len(full), (mean_size, full)
        print('PASS', database, expected, 'rows; schema v13; UInt32/Int32; self+remote; DATA zeros and EOM values preserved', flush=True)
    except Exception:
        print((root / 'stdout').read_text())
        print((root / 'rspamd.log').read_text()[-30000:])
        raise
    finally:
        proc.terminate()
        proc.wait(timeout=10)
