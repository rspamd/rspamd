# Rspamd workers

Rspamd defines several types of worker processes. Each type is designed for its specific
purpose, for example to scan mail messages, to perform control actions, such as learning or
statistic grabbing. There is also flexible worker type named `lua` worker that allows
to run any lua script as rspamd worker providing proxy from rspamd lua API.

## Worker types

Currently rspamd defines the following worker types:

- [normal](normal.md): this worker is designed to scan mail messages
- [controller](controller.md): this worker performs configuration actions, such as
learning, adding fuzzy hashes and serving web interface requests
- [fuzzy_storage](fuzzy_storage.md): stores fuzzy hashes
- [lua](lua_worker.md): runs custom lua scripts

## Workers connections

All client applications should interact with two main workers: `normal` and `controller`.
Both of these workers use `HTTP` protocol for all operations and rely on HTTP headers
to get extra information from a client. Depending on network configuration, it might be
useful to bind all workers to the loopback interface preventing all interaction from the
outside. Rspamd workers are **not** supposed to run in an unprotected environment, such as
Internet. Currently there is neither secrecy nor integrity control in these protocols and
using of plain HTTP might leak sensitive information.

[Fuzzy worker](fuzzy_storage.md) is different: it is intended to serve external requests, however, it
listens on an UDP port and does not save any state information.

## Common workers options

All workers shares a set of common options. Here is a typical example of a normal
worker configuration that uses merely common worker options:

~~~nginx
worker {
    type = "normal";
    bind_socket = "*:11333";
}
~~~

Here are options available to all workers:

- `type` - a **mandatory** string that defines type of worker.
- `bind_socket` - a string that defines bind address of a worker.
- `count` - number of worker instances to run (some workers ignore that option, e.g. `fuzzy_storage`)

`bind_socket` is the mostly common used option. It defines the address where worker should accept
connections. Rspamd allows both names and IP addresses for this option:

~~~nginx
bind_socket = "localhost:11333";
bind_socket = "127.0.0.1:11333";
bind_socket = "[::1]:11333"; # note that you need to enclose ipv6 in '[]'
~~~

Also universal listening addresses are defined:

~~~nginx
bind_socket = "*:11333"; # any ipv4 and ipv6 address
bind_socket = "*v4:11333"; # any ipv4 address
bind_socket = "*v6:11333"; # any ipv6 address
~~~

Moreover, you can specify systemd sockets if rspamd is invoked by systemd:

~~~nginx
bind_socket = "systemd:1"; # the first socket passed by systemd throught environment
~~~

You can specify multiple `bind_socket` options to listen on as many addresses as
you want.