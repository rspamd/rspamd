---
layout: doc_worker_add
title: Controller worker
---
# Controller worker

Controller worker is used to manage rspamd stats, to learn rspamd and to serve WebUI.

Internally, the controller worker is just a web server that accepts requests and sends replies using JSON serialization.
Each command is defined by URL. Some commands are read only and are considered as `unprivileged` whilst other commands, such as
maps modification, config modifications and learning requires higher level of privileges: `enable` level. The differece between levels is specified
by password. If only one password is specified in the configuration, it is used for both type of commands.

## Controller configuration

Rspamd controller worker supports the following options:

* `password`: password for read-only commands
* `enable_password`: password for write commands
* `secure_ip`: list or map with IP addresses that are treated as `secure` so **all** commands are allowed from these IPs **without** passwords
* `static_dir`: directory where interface static files are placed (usually `${WWWDIR}`)
* `stats_path`: path where controller save persistent stats about rspamd (such as scanned messages count)

## Encryption support

To generate a keypair for the scanner you could use:

    rspamadm keypair -u

After that keypair should appear as following:

~~~ucl
keypair {
    pubkey = "tm8zjw3ougwj1qjpyweugqhuyg4576ctg6p7mbrhma6ytjewp4ry";
    privkey = "ykkrfqbyk34i1ewdmn81ttcco1eaxoqgih38duib1e7b89h9xn3y";
}
~~~

You can use its **public** part thereafter when scanning messages as following:

    rspamc --key tm8zjw3ougwj1qjpyweugqhuyg4576ctg6p7mbrhma6ytjewp4ry <file>

## Passwords encryption

Rspamd now suggests to encrypt passwords when storing them in a configuration. Currently, it uses `PBKDF2-Blake2` function to derive key from a password. To encrypt key, you can use `rspamadm pw` command as following:

    rspamadm pw
    Enter passphrase: <hidden input>
    $1$cybjp37q4w63iogc4erncz1tgm1ce9i5$kxfx9xc1wk9uuakw7nittbt6dgf3qyqa394cnradg191iqgxr8kb

You can use that line as `password` and `enable_password` values.

## Supported commands

* `/auth`
* `/symbols`
* `/actions`
* `/maps`
* `/getmap`
* `/graph`
* `/pie`
* `/history`
* `/historyreset` (priv)
* `/learnspam` (priv)
* `/learnham` (priv)
* `/saveactions` (priv)
* `/savesymbols` (priv)
* `/savemap` (priv)
* `/scan`
* `/check`
* `/stat`
* `/statreset` (priv)
* `/counters`
