"""Helpers that check what the clickhouse plugin sent to dummy_clickhouse.py."""

import ast
import json
import os
import re

EXTRA_COLUMN = 'ProfTestExtra'
PROFILE_COLUMNS = ['ProfileReason', 'Profile.Names', 'Profile.Times',
                   'Profile.SyncTimes', 'Profile.Flags']


def _records(path):
    if not os.path.exists(path):
        return []
    res = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                res.append(json.loads(line))
    return res


def _columns(query):
    m = re.match(r'^INSERT INTO rspamd \((.*)\) FORMAT TabSeparated$', query)
    if not m:
        return None
    return m.group(1).split(',')


def _main_inserts(path):
    res = []
    for r in _records(path):
        if r['kind'] == 'insert':
            cols = _columns(r['query'])
            if cols is not None:
                res.append((cols, r['body']))
    return res


def stub_main_insert_count(path):
    """Number of INSERTs into the main table seen so far"""
    return len(_main_inserts(path))


def stub_statements(path):
    """All non-INSERT statements seen so far"""
    return [r['sql'] for r in _records(path) if r['kind'] != 'insert']


def stub_check_inserts(path, profile, symbols, selected='CHPROF_SYM'):
    """Checks every INSERT into the main table.

    profile: whether the five profile columns are expected
    symbols: whether enable_symbols is on (the profile block then follows
             Groups.Scores, otherwise IPNet)
    """
    inserts = _main_inserts(path)
    if not inserts:
        raise AssertionError('no INSERT into the main table was recorded')
    nrows = 0
    for cols, body in inserts:
        anchor = 'Groups.Scores' if symbols else 'IPNet'
        assert ('Symbols.Names' in cols) == symbols, cols
        assert cols.count(anchor) == 1, cols
        # The extra column is configured: it always comes last, right after
        # the profile block (or after Groups.Scores when there is none)
        assert cols.count(EXTRA_COLUMN) == 1 and cols[-1] == EXTRA_COLUMN, cols
        if symbols or profile:
            before = cols[-2]
            expected = PROFILE_COLUMNS[-1] if profile else anchor
            assert before.strip('`') == expected.strip('`') or before == expected, cols
        if profile:
            for c in PROFILE_COLUMNS:
                assert cols.count(c) == 1, 'column %s in %s' % (c, cols)
            pos = cols.index('ProfileReason')
            assert cols[pos - 1] == anchor, cols
            assert cols[pos:pos + 5] == PROFILE_COLUMNS, cols
        else:
            for c in cols:
                assert c != 'ProfileReason' and not c.startswith('Profile.'), cols
        for line in body.split('\n'):
            if not line:
                continue
            nrows += 1
            fields = line.split('\t')
            assert len(fields) == len(cols), \
                'row has %d fields for %d columns: %r' % (len(fields), len(cols), line)
            if profile:
                pos = cols.index('ProfileReason')
                assert fields[pos] == 'sampled', fields[pos]
                arrays = [ast.literal_eval(fields[pos + i]) for i in range(1, 5)]
                lens = {len(a) for a in arrays}
                assert len(lens) == 1 and lens != {0}, arrays
                assert selected in arrays[0], arrays[0]
                idx = arrays[0].index(selected)
                assert arrays[1][idx] >= 0 and arrays[2][idx] >= 0, arrays
    return nrows
