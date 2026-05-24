"""Helpers for choosing PID file paths that don't collide under pabot.

All dummy_* helper services historically wrote `/tmp/dummy_<name>.pid`.
Under parallel test execution this collides between workers and between
multiple instances of the same service on different ports. This module
derives a unique path from:

  * RSPAMD_TMP_PREFIX env var (set by test/functional/lib/vars.py at
    import time -> /tmp/rspamd-functional-<worker_index>)
  * The service name (e.g. "clamav", "fprot", "ssl")
  * A discriminator (port number for TCP services, sanitized socket
    path for unix-socket services)

Fall back to /tmp when RSPAMD_TMP_PREFIX is unset (ad-hoc utility
invocations outside the test harness).
"""

import os
import re


def _tmp_root():
    root = os.environ.get('RSPAMD_TMP_PREFIX', '/tmp')
    try:
        os.makedirs(root, exist_ok=True)
    except OSError:
        root = '/tmp'
    return root


def pid_path(service, discriminator):
    """Return a worker- and instance-unique pid file path.

    `discriminator` is normally a port number; for unix-socket services
    pass the socket path and we'll hash it down to a short suffix.
    """
    disc = str(discriminator)
    # Socket paths contain slashes; keep filenames flat.
    disc = re.sub(r'[^A-Za-z0-9_.-]+', '_', disc).strip('_') or '0'
    return os.path.join(_tmp_root(), 'dummy_{}-{}.pid'.format(service, disc))
