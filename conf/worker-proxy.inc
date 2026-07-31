# Proxy worker setup
# Please don't modify this file as your changes might be overwritten with
# the next update.
#
# You can modify 'local.d/worker-proxy.inc' to add and merge
# parameters defined inside this section
#
# You can modify 'override.d/worker-proxy.inc' to strictly override all
# parameters defined inside this section
#
# See https://rspamd.com/doc/faq.html#what-are-the-locald-and-overrided-directories
# for details
# Module documentation: https://rspamd.com/doc/workers/rspamd_proxy.html

milter = yes; # Enable milter mode

# This timeout is mostly specific to the milter mode.
# Please also bear in mind that if this timeout is longer than `task_timeout`,
# your messages might be processed for much longer due to this timeout (this is
# true for self-scan mode).
# If this behaviour is not desired, then it is recommended to reduce and adjust this
# value accordingly
timeout = 60s;

upstream "local" {
  default = yes;
  hosts = "localhost";

  # Token bucket load balancing: distributes load based on message size
  # and current backend utilization (useful with multiple backends)
  token_bucket {
    max_tokens = 10000;  # Maximum token capacity per backend
    scale = 1024;        # Bytes per token (1KB = 1 token)
    min_tokens = 1;      # Minimum tokens required for selection
    base_cost = 10;      # Base cost per request regardless of size
  }
}

count = 1; # Do not spawn too many processes of this type
max_retries = 5; # How many times master is queried in case of failure
discard_on_reject = false; # Discard message instead of rejection
quarantine_on_reject = false; # Tell MTA to quarantine rejected messages
spam_header = "X-Spam"; # Use the specific spam header
reject_message = "Spam message rejected"; # Use custom rejection message

# Allow client-named message sources: the `File`/`Path`/`Shm`/`Shm-Offset`/
# `Shm-Length` headers, the `File` query argument, and the v3
# `file`/`shm`/`shm_offset`/`shm_length` metadata keys, which make rspamd read
# a path or map a shared memory object chosen by the client. TCP listeners
# only: unix sockets always permit these inputs, since filesystem permissions
# control access there.
# Do not enable on a listener reachable from untrusted networks. Authentication
# and encryption do NOT authorize this capability.
# `true` here for backwards compatibility; it becomes `false` by default in the
# next major release.
allow_file_and_shm_inputs = true;

# Upper bound on concurrent client connections served by a proxy process.
# 0 (the default) means unlimited; a finite value bounds concurrency.
# max_connections = 0;
