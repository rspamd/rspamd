# Normal scanner worker setup
# Please don't modify this file as your changes might be overwritten with
# the next update.
#
# You can modify 'local.d/worker-normal.inc' to add and merge
# parameters defined inside this section
#
# You can modify 'override.d/worker-normal.inc' to strictly override all
# parameters defined inside this section
#
# See https://rspamd.com/doc/faq.html#what-are-the-locald-and-overrided-directories
# for details
# Module documentation: https://rspamd.com/doc/workers/normal.html

mime = true;

# Allow client-named message sources: the `File`/`Path`/`Shm`/`Shm-Offset`/
# `Shm-Length` headers and the v3 `file`/`shm`/`shm_offset`/`shm_length`
# metadata keys, which make rspamd read a path or map a shared memory object
# chosen by the client. TCP listeners only: unix sockets always permit these
# inputs, since filesystem permissions control access there.
# Do not enable on a listener reachable from untrusted networks. Authentication
# and encryption do NOT authorize this capability.
# `true` here for backwards compatibility; it becomes `false` by default in the
# next major release.
allow_file_and_shm_inputs = true;
