#!/usr/bin/env python3
"""
Script to save coverage info for C source files in JSON for coveralls.io

When C code compiled with --coverage flag, for each object files *.gcno is
generated, it contains information to reconstruct the basic block graphs and
assign source line numbers to blocks

When binary executed *.gcda file is written on exit, with same base name as
corresponding *.gcno file. It contains some summary information, counters, e.t.c.

gcov(1) utility can be used to get information from *.gcda file and write text
reports to *.gocov file (one file for each source file from which object was compiled).

The script finds *.gcno files, uses gcov to generate *.gcov files, parses them
and accomulates statistics for all source files.

This script was written with quite a few assumptions:

    * Code was build using absolute path to source directory (and absolute path
      stored in object file debug sylmbols).

    * Current directory is writable and there is no useful *.gcov files in it
      (becase they will be deleted).

    * Object file has same base name as *.gcno file (e. g. foo.c.gcno and foo.c.o).
      This is the case for cmake builds, but probably not for other build systems

    * Source file names contain only ASCII characters.
"""

import argparse
from collections import defaultdict
from glob import glob
import hashlib
import json
import os
from os.path import isabs, join, normpath, relpath
import os.path
import subprocess
import sys


def warn(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def parse_gcov_file(gcov_file):
    """Parses the content of .gcov file written by gcov -i

    Returns:
      str: Source file name
      dict: coverage info { line_number: hits }
    """
    count = {}
    with open(gcov_file) as fh:
        for line in fh:
            tag, value = line.split(':')
            if tag == 'file':
                src_file = value.rstrip()
            elif tag == 'lcount':
                line_num, exec_count = value.split(',')
                count[int(line_num)] = int(exec_count)

    return src_file, count


def run_gcov(filename, coverage, args):
    """ * run gcov on given file
        * parse generated .gcov files and update coverage structure
        * store source file md5 (if not yet stored)
        * delete .gcov files
    """
    if args.verbose:
        warn("calling:", 'gcov', '-i', filename)
        stdout = None
    else:
        # gcov is noisy and don't have quit flag so redirect stdout to /dev/null
        stdout = subprocess.DEVNULL

    subprocess.check_call(['gcov', '-i', filename], stdout=stdout)

    for gcov_file in glob('*.gcov'):
        if args.verbose:
            warn('parsing', gcov_file)
        src_file, count = parse_gcov_file(gcov_file)
        os.remove(gcov_file)

        if src_file not in coverage:
            coverage[src_file] = defaultdict(int, count)
        else:
            # sum execution counts
            for line, exe_cnt in count.items():
                coverage[src_file][line] += exe_cnt


def main():
    parser = argparse.ArgumentParser(
        description='Save gcov coverage results in JSON file for coveralls.io.')
    parser.add_argument(
        '-v',
        '--verbose',
        action="store_true",
        help='Display additional informaton and gcov command output.')
    parser.add_argument(
        '-e',
        '--exclude',
        action='append',
        metavar='DIR',
        help=
        ("Don't look for .gcno/.gcda files in this directories (repeat option to skip several directories). "
         "Path is relative to the dirictory where script was started, e. g. '.git'"))
    parser.add_argument(
        '-p',
        '--prefix',
        action='append',
        help=
        ("Strip this prefix from absolute path to source file. "
         "If this option is provided, then only files with given prefixex in absolute path "
         "will be added to coverage (option can be repeated)."))
    parser.add_argument(
        '--out',
        type=argparse.FileType('w'),
        required=True,
        metavar='FILE',
        help='Save JSON payload to this file')
    args = parser.parse_args()

    # ensure that there is no unrelated .gcov files in current directory
    for gcov_file in glob('*.gcov'):
        os.remove(gcov_file)
        warn("Warning: {} deleted".format(gcov_file))

    # dict { src_file_name: {line1: exec_count1, line2: exec_count2, ...} }
    coverage = {}

    # find . -name '*.gcno' (respecting args.exclude)
    for root, dirs, files in os.walk('.'):
        for f in files:
            # Usually gcov called with a source file as an argument, but this
            # name used only to find .gcno and .gcda files.  To find source
            # file information from debug symbols is used.  So we can call gcov
            # on .gcno file.
            if f.endswith('.gcno'):
                run_gcov(join(root, f), coverage, args)

        # don't look into excluded dirs
        for subdir in dirs:
            # path relative to start dir
            path = normpath(join(root, subdir))
            if path in args.exclude:
                if args.verbose:
                    warn('directory "{}" excluded'.format(path))
                dirs.remove(subdir)

    # prepare JSON pyload for coveralls.io API
    # https://docs.coveralls.io/api-introduction
    coveralls_data = {'source_files': []}

    for src_file in coverage:
        # filter by prefix and save path with stripped prefix
        src_file_rel = src_file
        if args.prefix and isabs(src_file):
            for prefix in args.prefix:
                if src_file.startswith(prefix):
                    src_file_rel = relpath(src_file, start=prefix)
                    break
            else:
                # skip file outside given prefixes
                # it can be e. g. library include file
                if args.verbose:
                    warn('file "{}" is not mathced by prefix, skipping'.format(src_file))
                continue

        try:
            with open(src_file, mode='rb') as fh:
                line_count = sum(1 for _ in fh)
                fh.seek(0)
                md5 = hashlib.md5(fh.read()).hexdigest()
        except OSError as err:
            # skip files for which source file is not available
            warn(err, 'not adding to coverage')
            continue

        coverage_array = [None] * line_count

        for line_num, exe_cnt in coverage[src_file].items():
            # item at index 0 representing the coverage for line 1 of the source code
            assert 1 <= line_num <= line_count
            coverage_array[line_num - 1] = exe_cnt

        coveralls_data['source_files'].append({
            'name': src_file_rel,
            'coverage': coverage_array,
            'source_digest': md5
        })

    args.out.write(json.dumps(coveralls_data))

    if args.verbose:
        warn('Coverage for {} source files was written'.format(
            len(coveralls_data['source_files'])))


if __name__ == '__main__':
    main()
