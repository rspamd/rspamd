#!/usr/bin/env python3

from __future__ import print_function

import argparse
import json
import os
import sys
import codecs

import requests

# Python 2/3 compatibility
if sys.version_info.major > 2:
    xrange = range

# install path to repository mapping
# if path mapped to None, it means that the file should be ignored (i.e. test file/helper)
# first matched path counts.
# terminating slash should be added for directories
path_mapping = [
    ("${install-dir}/share/rspamd/lib/fun.lua", None),
    ("${install-dir}/share/rspamd/lib/", "lualib/"),
    ("${install-dir}/share/rspamd/rules/" , "rules/"),
    ("${install-dir}/share/rspamd/lib/torch/" , None),
    ("${build-dir}/CMakeFiles/", None),
    ("${build-dir}/contrib/", None),
    ("${build-dir}/test", None),
    ("${project-root}/test/lua/", None),
    ("${project-root}/test/", None),
    ("${project-root}/clang-plugin/", None),
    ("${project-root}/CMakeFiles/", None),
    ("${project-root}/contrib/", None),
    ("${project-root}/", ""),
    ("contrib/", None),
    ("CMakeFiles/", None),
]

parser = argparse.ArgumentParser(description='')
parser.add_argument('--input', required=True, nargs='+', help='input files')
parser.add_argument('--output', help='output file)')
parser.add_argument('--root', default="/rspamd/src/github.com/rspamd/rspamd", help='repository root)')
parser.add_argument('--install-dir', default="/rspamd/install", help='install root)')
parser.add_argument('--build-dir', default="/rspamd/build", help='build root)')
parser.add_argument('--token', help='If present, the file will be uploaded to coveralls)')


def merge_coverage_vectors(c1, c2):
    assert(len(c1) == len(c2))

    for i in range(0, len(c1)):
        if c1[i] is None and c2[i] is None:
            pass
        elif type(c1[i]) is int and c2[i] is None:
            pass
        elif c1[i] is None and type(c2[i]) is int:
            c1[i] = c2[i]
        elif type(c1[i]) is int and type(c2[i]) is int:
            c1[i] += c2[i]
        else:
            raise RuntimeError("bad element types at %d: %s, %s", i, type(c1[i]), type(c1[i]))

    return c1


def normalize_name(name):
    name = os.path.normpath(name)
    if not os.path.isabs(name):
        name = os.path.abspath(repository_root + "/" + name)
    for k in path_mapping:
        if name.startswith(k[0]):
            if k[1] is None:
                return None
            else:
                name = k[1] + name[len(k[0]):]
                break
    return name

def merge(files, j1):
    for sf in j1['source_files']:
        name = normalize_name(sf['name'])
        if name is None:
            continue
        if name in files:
            files[name]['coverage'] = merge_coverage_vectors(files[name]['coverage'], sf['coverage'])
        else:
            sf['name'] = name
            files[name] = sf

    return files

def prepare_path_mapping():
    for i in range(0, len(path_mapping)):
        new_key = path_mapping[i][0].replace("${install-dir}", install_dir)
        new_key = new_key.replace("${project-root}", repository_root)
        new_key = new_key.replace("${build-dir}", build_dir)

        path_mapping[i] = (new_key, path_mapping[i][1])

if __name__ == '__main__':
    args = parser.parse_args()

    repository_root = os.path.abspath(os.path.expanduser(args.root))
    install_dir = os.path.normpath(os.path.expanduser(args.install_dir))
    build_dir = os.path.normpath(os.path.expanduser(args.build_dir))

    prepare_path_mapping()

    with codecs.open(args.input[0], 'r', encoding='utf-8') as fh:
        j1 = json.load(fh)

    files = merge({}, j1)
    for i in range(1, len(args.input)):
        with codecs.open(args.input[i], 'r', encoding='utf-8') as fh:
            j2 = json.load(fh)

        files = merge(files, j2)

        if 'git' not in j1 and 'git' in j2:
            j1['git'] = j2['git']
        if 'service_name' not in j1 and 'service_name' in j2:
            j1['service_name'] = j2['service_name']
        if 'service_job_id' not in j1 and 'service_job_id' in j2:
            j1['service_job_id'] = j2['service_job_id']


        if os.getenv('CIRCLECI'):
            j1['service_name'] = 'circleci'
            j1['service_job_id'] = os.getenv('CIRCLE_BUILD_NUM')
        elif os.getenv('DRONE') == 'true':
            j1['service_name'] = 'drone'
            j1['service_branch'] = os.getenv('DRONE_COMMIT_BRANCH')
            j1['service_build_url'] = os.getenv('DRONE_BUILD_LINK')
            j1['service_number'] = os.getenv('DRONE_BUILD_NUMBER')
            j1['commit_sha'] = os.getenv('DRONE_COMMIT_SHA')
            if os.getenv('DRONE_BUILD_EVENT') == 'pull_request':
                j1['service_pull_request'] = os.getenv('DRONE_PULL_REQUEST')
            # git data can be filled by cpp-coveralls, but in our layout it can't find repo
            # so we can override git info witout merging
            j1['git'] = {
                'head': {
                    'id': j1['commit_sha'],
                    'author_email': os.getenv('DRONE_COMMIT_AUTHOR_EMAIL'),
                    'message': os.getenv('DRONE_COMMIT_MESSAGE')
                },
                'branch': j1['service_branch'],
                'remotes': [{
                    'name': 'origin',
                    'url': os.getenv('DRONE_GIT_HTTP_URL')
                }]
            }


    j1['source_files'] = list(files.values())

    if args.output:
        with open(args.output, 'w') as f:
            f.write(json.dumps(j1))

    if args.token:
        j1['repo_token'] = args.token
        try:
            r = requests.post('https://coveralls.io/api/v1/jobs', files={"json_file": json.dumps(j1)})
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            print("Failed to send data to coveralls: %s" % e)
            sys.exit()

        try:
            response = r.json()
            print("[coveralls] %s" % response['message'])
            if 'url' in response:
                print("[coveralls] Uploaded to %s" % response['url'])
        except json.decoder.JSONDecodeError:
            print("Bad resonse: '%s'" % r.text)
