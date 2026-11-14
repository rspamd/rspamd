# Rspamd web interface

## Overview

This is a simple control interface for rspamd spam filtering system.
It provides basic functions for setting metric actions, scores,
viewing statistic and learning.

<img src="https://rspamd.com/img/webui.png" class="img-responsive" alt="Webui screenshot">
<img src="https://rspamd.com/img/webui_throughput.png" class="img-responsive" alt="Webui screenshot">

## Rspamd setup

Actions thresholds and symbols scores that are changed in the interface are stored as the dynamic
configuration (`actions` and `scores` modules of `dynconf`). It is enabled by default: the values are kept
in the `rspamd_dynconf.json` file in the rspamd database directory (`$DBDIR`), which must be writable for the
rspamd user, and every worker picks them up from there. The location and the other options can be changed in
the `dynconf` section (see `conf/rspamd.conf`):

~~~ucl
dynconf {
 path = "/var/lib/rspamd/rspamd_dynconf.json";
}
~~~

A threshold or a score that the interface changes has the priority 3: it replaces what the main file (priority 0)
and `local.d` (1) say, but not what `override.d` (10) says. The interface refuses such a change with an error that
names the entry; an override that is already stored (written by a node, or by hand) and meets such an entry is
skipped with a warning. An emptied field of the interface (`null`) removes the override of that action or symbol:
the static value is back.

The names that an override holds are checked when it is written: an unknown symbol or action is an error.
What a backend delivers (the periodic check, the start of a worker, `rspamadm configdump --dynamic`) is applied
leniently: an entry that names a symbol that does not exist any more (a disabled plugin, a renamed symbol) is
skipped with a warning, the rest is applied, and the skipped entries are listed in the dump of the module
(`/plugins/dynconf/dump`, the `skipped` attribute) and in `last_error` of the backend, for as long as they stay
skipped. They are offered to the subscribers again at every check, so a symbol that appears later (a composite of a
map) gets its override then. A stale entry is kept in the stored override, it does not stop a write that does not
touch it, and an emptied field for it removes it.

The previous implementations are deprecated. The primary controller imports their data once, into the modules that
hold no overrides yet: the file of the `dynamic_conf` option of the `options` section is read and renamed to
`<file>.imported`; the Redis hash of the `dynamic_conf {}` module is read when `dynconf` uses the `redis` backend
(`backend = "redis"`), it is not deleted but marked as imported. Nothing switches the backend to Redis by itself:
when a `dynamic_conf {}` section with Redis servers is configured and `dynconf` uses another backend (or is disabled
with `enabled = false`, which needs the `enabled = false` line removed as well), an error is logged at every start and
the Redis data is not applied. Entries that cannot be changed dynamically because `override.d` defines them are not
imported either, they are logged as skipped. Only scores and thresholds are imported: the lists
`symbols_disabled` and `symbols_enabled` of the old module never took effect at runtime and are logged as skipped.
The `dynamic_conf` section is not needed after the import.

Then controller worker should be configured:

~~~ucl
worker {
        type = "controller";
        bind_socket = "localhost:11334";
        count = 1;
        # Password for normal commands (use rspamadm pw)
        password = "$2$anydoddx67ggcs74owybhcwqsq3z67q4$udympbo8pfcfqkeiiuj7gegabk5jpt8edmhseujhar9ooyuzig5b";
        # Password for privileged commands (use rspamadm pw)
        enable_password = "$2$nx6sqkxtewx9c5s3hxjmabaxdcr46pk9$45qajkbyqx77abapiqugpjpsojj38zcqn7xnp3ekqyu674koux4b";
        # Path to webiu static files
        static_dir = "${WWWDIR}";
}
~~~

Password option should be changed for sure for your specific configuration. Encrypted password using is encouraged (`rspamadm pw --encrypt`).

## Interface setup

Interface itself is written in pure HTML5/js and, hence, it requires zero setup.
Just enter a password for webui access and you are ready.

## Development

For developers looking to contribute to or modify the WebUI, see [ARCHITECTURE.md](ARCHITECTURE.md) for:
- Code structure and organization
- Technology stack details
- Development patterns and practices

## Contact information

For all questions related to this product please see the [support page](https://rspamd.com/support.html)
