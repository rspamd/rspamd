---
layout: doc_modules
title: DCC module
---
# DCC module

This modules performs [DCC](http://www.dcc-servers.net/dcc/) lookups to determine
the *bulkiness* of a message (e.g. how many recipients have seen it).

Identifying bulk messages is very useful in composite rules e.g. if a message is
from a freemail domain *AND* the message is reported as bulk by DCC then you can
be sure the message is spam and can assign a greater weight to it.

Please view the License terms on the DCC website before you enable this module.

## Module configuration

This module requires that you have the `dccifd` daemon configured, running and
working correctly.  To do this you must download and build the [latest DCC client]
(https://www.dcc-servers.net/dcc/source/dcc.tar.Z).  Once installed, edit
`/var/dcc/dcc_conf` set `DCCIFD_ENABLE=on` and set `DCCM_LOG_AT=NEVER` and
`DCCM_REJECT_AT=MANY`, then start the daemon by running `/var/dcc/libexec/rcDCC start`.

Once the `dccifd` daemon is started it will listen on the UNIX domain socket /var/dcc/dccifd
and all you have to do is tell the rspamd where `dccifd` is listening:

~~~ucl
dcc {
    host = "/var/dcc/dccifd";
    # Port is only required if `dccifd` listens on a TCP socket
    # port = 1234
}
~~~

Once this module is configured it will write the DCC output to the rspamd as each
message is scanned:

`````
Apr  5 14:19:53 mail1-ewh rspamd: (normal) lua; dcc.lua:98: sending to dcc: client=217.78.2.204#015DNSERROR helo="003b046f.slimabs.top" envfrom="23SecondAbs@slimabs.top" envrcpt="xxxx@xxxx.com"
Apr  5 14:19:53 mail1-ewh rspamd: (normal) lua; dcc.lua:65: DCC result=R disposition=R header="X-DCC--Metrics: xxxxx.xxxx.com 1282; bulk Body=1 Fuz1=1 Fuz2=many"
`````

Any messages that DCC returns a *reject* result for (based on the configured `DCCM_REJECT_AT`
value) will cause the symbol `DCC_BULK` to fire.
