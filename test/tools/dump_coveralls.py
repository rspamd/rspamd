#!/usr/bin/env python3

# Small tool to dump JSON payload for coveralls.io API

import json
from operator import itemgetter
import os
import sys


def warn(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def dump_file(json_file):
    """Dumps coveralls.io API payload stored in json_file
       Returns: 0 if successful, 1 otherwise
    """
    try:
        with open(json_file, encoding='utf8') as f:
            data = json.load(f)
    except OSError as err:
        warn(err)
        return os.EX_DATAERR
    except json.decoder.JSONDecodeError:
        warn("{}: json parsing error".format(json_file))
        return 1

    if 'source_files' not in data:
        warn("{}: no source_files, not a coveralls.io payload?".format(json_file))
        return 1

    print("{} ({} soource files)".format(json_file, len(data['source_files'])))

    for src_file in sorted(data['source_files'], key=itemgetter('name')):
        covered_lines = not_skipped_lines = 0
        for cnt in src_file['coverage']:
            if cnt is None:
                continue
            not_skipped_lines += 1
            if cnt > 0:
                covered_lines += 1
        if not_skipped_lines > 0:
            coverage = "{:.0%}".format(covered_lines / not_skipped_lines)
        else:
            coverage = 'N/A'

        print("\t{:>3} {}".format(coverage, src_file['name']))

    return 0


def main():
    if (len(sys.argv) < 2):
        warn("usage: {} file.json ...".format(sys.argv[0]))
        return os.EX_USAGE

    exit_status = 0
    for f in sys.argv[1:]:
        exit_status += dump_file(f)

    return exit_status


if __name__ == '__main__':
    sys.exit(main())
