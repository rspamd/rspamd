#!/usr/bin/env python3
"""
Small script to upload file using HTTP PUT
"""

import argparse
import os
import sys

import requests


def main():
    parser = argparse.ArgumentParser(
        description='Upload a file usgin HTTP PUT method',
        epilog=(
            "To use HTTP Auth set HTTP_PUT_AUTH environment variable to user:password\n"
            "Example: %(prog)s file1 file2 https://example.com/dir/"))
    parser.add_argument(
        "file", type=argparse.FileType('rb'), nargs='+', help="File to upload")
    parser.add_argument(
        "dir_url", help="Remote URL (path to a directory, must include a trailing /)")
    args = parser.parse_args()

    if not args.dir_url.endswith('/'):
        parser.error("URL must end with /")

    http_auth = os.getenv('HTTP_PUT_AUTH')
    if http_auth:
        user, password = http_auth.split(':')
        auth = (user, password)
    else:
        auth = None

    exit_code = 0

    for fh in args.file:
        try:
            r = requests.put(args.dir_url + fh.name, data=fh, auth=auth, timeout=(45, 90))
            r.raise_for_status()
            print("{} uploaded to {}".format(fh.name, r.url))
        except (requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as err:
            print(err, file=sys.stderr)
            exit_code = 1

    return exit_code


if __name__ == '__main__':
    sys.exit(main())
