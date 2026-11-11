# Controller worker setup
# Please don't modify this file as your changes might be overwritten with
# the next update.
#
# You can modify 'local.d/worker-controller.inc' to add and merge
# parameters defined inside this section
#
# You can modify 'override.d/worker-controller.inc' to strictly override all
# parameters defined inside this section
#
# See https://rspamd.com/doc/faq.html#what-are-the-locald-and-overrided-directories
# for details
# Module documentation: https://rspamd.com/doc/workers/controller.html

count = 1;
password = "q1";
secure_ip = "127.0.0.1";
secure_ip = "::1";
static_dir = "${WWWDIR}";

# Allow client-named message sources: the `File`/`Path`/`Shm`/`Shm-Offset`/
# `Shm-Length` headers and the v3 `file`/`shm`/`shm_offset`/`shm_length`
# metadata keys, which make rspamd read a path or map a shared memory object
# chosen by the client. TCP listeners only: unix sockets always permit these
# inputs, since filesystem permissions control access there.
# Do not enable on a listener reachable from untrusted networks. Neither
# `password`/`enable_password`, nor a `secure_ip` match, nor an encrypted
# connection authorizes this capability: it is a separate one.
# `true` here for backwards compatibility; it becomes `false` by default in the
# next major release.
allow_file_and_shm_inputs = true;

# Upper bound on concurrent connections served by a controller process.
# 0 (the default) means unlimited; a finite value bounds concurrency.
# max_connections = 0;
