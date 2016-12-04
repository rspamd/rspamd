---
layout: doc
title: Setting up encrypted tunnel using stunnel
---
# Setting up encrypted tunnel using stunnel

To implement encrypted communication between Redis masters and slaves, we recommend using [stunnel](https://www.stunnel.org). Stunnel works as TLS encryption wrapper between client and server.

This step-by-step tutorial will explain how to install and configure `stunnel` proxies on FreeBSD client and server. Configuration procedures for other operating systems are very similar. For simplicity, this tutorial only covers replication to one client host as this configuration does not require individual preshared keys for each of the clients.

Assuming we have 3 Redis instances on both `server` and `client`, listening sockets on the `server` (master side):

|instance|Redis socket|stunnel socket|
|---|---|---|
|`redis`|localhost:6379|-|
|`bayes`|localhost:6378|master.example.com:6478|
|`fuzzy`|localhost:6377|master.example.com:6477|

As the instance named `redis` should not be mirrored, we will replicate `fuzzy` and `bayes` instances. So we need to setup 2 TLS tunnels.

## Installation

First install the `security/stunnel` package:

```sh
# pkg install stunnel
```

Create pid-file directory:

```sh
# mkdir /var/run/stunnel && chown stunnel:stunnel /var/run/stunnel
```

To enable `stunnel` add the following lines to the `/etc/rc.conf`:

```sh
stunnel_enable="YES"
stunnel_pidfile="/var/run/stunnel/stunnel.pid"
```

## Server configuration (master side)

`/usr/local/etc/stunnel/stunnel.conf`:

```
setuid = stunnel
setgid = nogroup

pid = /var/run/stunnel/stunnel.pid

[bayes]
accept  = 6478
connect = 6378
ciphers = PSK
PSKsecrets = /usr/local/etc/stunnel/psk.txt

[fuzzy]
accept  = 6477
connect = 6377
ciphers = PSK
PSKsecrets = /usr/local/etc/stunnel/psk.txt
```

## Client configuration (slave side)

`/usr/local/etc/stunnel/stunnel.conf`:

```
setuid = stunnel
setgid = nogroup

pid = /var/run/stunnel/stunnel.pid

[bayes]
client = yes
accept  = localhost:6478
connect = master.example.com:6478
ciphers = PSK
PSKsecrets = /usr/local/etc/stunnel/psk.txt

[fuzzy]
client = yes
accept  = localhost:6477
connect = master.example.com:6477
ciphers = PSK
PSKsecrets = /usr/local/etc/stunnel/psk.txt
```

## Preshared keys

Create `/usr/local/etc/stunnel/psk.txt` .
 The `psk.txt` file contains one line for each client:

`test1:oaP4EishaeSaishei6rio6xeeph3az`

> _Do not use example passwords._

As both `bayes` and `fuzzy` Redis instances located at the same host we can share the same key between them.

Since this file should be kept secret set secure permissions on it:

`# chmod 600 /usr/local/etc/stunnel/psk.txt`

## Starting stunnel

`# service stunnel start`

## Testing

From the client host use the `redis-cli` utility to connect to the remote instances:

```sh
# redis-cli -p 6477
# redis-cli -p 6478
```

Given that it connected, you are clear to proceed with [configuring replication between Redis instances](./redis_replication.html#slave-instances-configuration).
