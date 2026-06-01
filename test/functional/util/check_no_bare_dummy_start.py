#!/usr/bin/env python3
"""Guard against reintroducing the dummy-helper start/scan race.

Every dummy_* helper must be started through the centralized
``Start Dummy Service`` keyword (or one of the ``Run Dummy *`` /
``Start Dummy *`` wrappers) defined in ``test/functional/lib/rspamd.robot``.
Those wrappers block until the helper's PID file appears -- which each
helper writes only after it has bound and is listening -- so the rspamd
worker (or the test) never races a not-yet-listening helper.

A bare ``Start Process  .../dummy_<x>.py`` inside a suite bypasses that
barrier and reintroduces the flakiness this guard exists to prevent.
This script exits non-zero if it finds one.

Usage:
    python3 test/functional/util/check_no_bare_dummy_start.py
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.normpath(os.path.join(HERE, '..', 'cases'))
REPO = os.path.normpath(os.path.join(HERE, '..', '..', '..'))

# A line that starts a dummy helper directly via Robot's Process library.
BARE = re.compile(r'Start Process\b.*dummy_[A-Za-z0-9_]*\.py')


def main():
    offenders = []
    for root, _dirs, files in os.walk(CASES):
        for name in sorted(files):
            if not name.endswith('.robot'):
                continue
            path = os.path.join(root, name)
            with open(path, encoding='utf-8') as fh:
                for lineno, line in enumerate(fh, 1):
                    if line.lstrip().startswith('#'):
                        continue
                    if BARE.search(line):
                        offenders.append((path, lineno, line.strip()))

    if offenders:
        sys.stderr.write(
            "ERROR: bare 'Start Process ... dummy_*.py' found in functional "
            "suites.\n"
            "Start dummy helpers through the 'Start Dummy Service' keyword (or "
            "a\n"
            "Run Dummy * / Start Dummy * wrapper) in lib/rspamd.robot so they "
            "block\n"
            "until the helper is listening. Offending lines:\n\n")
        for path, lineno, text in offenders:
            sys.stderr.write(
                "  {}:{}: {}\n".format(os.path.relpath(path, REPO), lineno, text))
        return 1

    print("OK: no bare dummy_*.py 'Start Process' in {}".format(
        os.path.relpath(CASES, REPO)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
