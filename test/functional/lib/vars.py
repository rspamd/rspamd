#  Copyright 2024 Vsevolod Stakhov
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.


import os
import shutil
import socket


def _worker_index():
    """Return a stable per-worker index for parallel test runs.

    When run under pabot, PABOTEXECUTIONPOOLID is stable across all suites
    a given worker process executes (0..processes-1). PABOTQUEUEINDEX is a
    fallback for older pabot versions. Plain `robot` runs serial -> index 0
    -> identical port numbers as before this change.

    RSPAMD_WORKER_INDEX env var lets callers override (useful for ad-hoc
    parallel invocations outside pabot, e.g. xargs / GNU parallel).
    """
    for var in ('RSPAMD_WORKER_INDEX', 'PABOTEXECUTIONPOOLID', 'PABOTQUEUEINDEX'):
        v = os.environ.get(var)
        if v is not None and v.strip().lstrip('-').isdigit():
            return int(v)
    return 0


_WORKER_INDEX = _worker_index()
# 100 ports per worker. We currently use ~14 distinct ports; 100 leaves
# headroom for future services and keeps each worker's ports humanly
# distinguishable in logs (worker 3 -> 56789 + 300 = 57089).
_PORT_OFFSET = _WORKER_INDEX * 100

# Per-worker prefix for unix sockets and pid files that have historically
# lived directly in /tmp. Created at import time so utilities and robot
# keywords can place files here without further coordination.
RSPAMD_TMP_PREFIX = os.environ.get(
    'RSPAMD_TMP_PREFIX',
    '/tmp/rspamd-functional-{}'.format(_WORKER_INDEX),
)
try:
    os.makedirs(RSPAMD_TMP_PREFIX, exist_ok=True)
except OSError:
    # Fall back to /tmp if we cannot create the prefix dir (e.g. read-only
    # /tmp on weird CI). Collisions remain possible but at least imports work.
    RSPAMD_TMP_PREFIX = '/tmp'

CONTROLLER_ERRORS = True
HAVE_MILTERTEST = shutil.which('miltertest') and True or False
RSPAMD_EXTERNAL_RELAY_ENABLED = False
RSPAMD_KEY_PVT1 = 'ekd3x36tfa5gd76t6pa8hqif3ott7n1siuux68exbkk7ukscte9y'
RSPAMD_KEY_PUB1 = 'm8kneubpcjsb8sbsoj7jy7azj9fdd3xmj63txni86a8ye9ncomny'
RSPAMD_KEY_PUB2 = 'mbggdnw3tdx7r3ruakjecpf5hcqr4cb4nmdp1fxynx3drbyujb3y'
RSPAMD_KEY_PUB3 = 'zhypei8sartqrtow84dddgp5exh3gsr65kbw88wj7ppot1bwmuiy'
RSPAMD_LOCAL_ADDR = '127.0.0.1'
RSPAMD_MAP_WATCH_INTERVAL = '1min'
RSPAMD_PORT_CONTROLLER = 56790 + _PORT_OFFSET
RSPAMD_PORT_CONTROLLER_SLAVE = 56793 + _PORT_OFFSET
RSPAMD_PORT_FUZZY = 56791 + _PORT_OFFSET
RSPAMD_PORT_FUZZY_SLAVE = 56792 + _PORT_OFFSET
RSPAMD_PORT_NORMAL = 56789 + _PORT_OFFSET
RSPAMD_PORT_NORMAL_SLAVE = 56794 + _PORT_OFFSET
RSPAMD_PORT_PROXY = 56795 + _PORT_OFFSET
RSPAMD_PORT_CONTROLLER_SSL = 56796 + _PORT_OFFSET
RSPAMD_PORT_NORMAL_SSL = 56797 + _PORT_OFFSET
RSPAMD_PORT_CLAM = 2100 + _PORT_OFFSET
RSPAMD_PORT_FPROT = 2101 + _PORT_OFFSET
RSPAMD_PORT_FPROT2_DUPLICATE = 2102 + _PORT_OFFSET
RSPAMD_PORT_AVAST = 2103 + _PORT_OFFSET
RSPAMD_PORT_DUMMY_HTTP = 18080 + _PORT_OFFSET
RSPAMD_PORT_DUMMY_HTTPS = 18081 + _PORT_OFFSET
RSPAMD_PORT_DUMMY_HTTP_EARLY = 18083 + _PORT_OFFSET
RSPAMD_PORT_DUMMY_UDP = 5005 + _PORT_OFFSET
RSPAMD_PORT_DUMMY_SSL = 14433 + _PORT_OFFSET
RSPAMD_P0F_SOCKET = '{}/p0f.sock'.format(RSPAMD_TMP_PREFIX)
RSPAMD_REDIS_ADDR = '127.0.0.1'
RSPAMD_REDIS_PORT = 56379 + _PORT_OFFSET
RSPAMD_NGINX_ADDR = '127.0.0.1'
RSPAMD_NGINX_PORT = 56380 + _PORT_OFFSET
RSPAMD_GROUP = 'nogroup'
RSPAMD_USER = 'nobody'
SOCK_DGRAM = socket.SOCK_DGRAM
SOCK_STREAM = socket.SOCK_STREAM
