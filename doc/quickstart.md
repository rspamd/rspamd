---
layout: doc
title: Rspamd quick start
---

# Rspamd quick start

This guide describes the main procedures to get and start working with rspamd.

## Installing Rspamd from packages

### Arch, CentOS, Debian, Fedora, openSUSE, SLE, Ubuntu

The recommended way to install Rspamd is using binary packages from [our project on the openSUSE build service](https://software.opensuse.org/download.html?project=home%3Acebka&package=rspamd) which is expected to always offer the best available version.

Rspamd is also available in Debian's [testing](https://packages.debian.org/source/testing/rspamd) and [unstable](https://packages.debian.org/source/unstable/rspamd) distributions and the universe repository in [some versions](http://packages.ubuntu.com/search?keywords=rspamd&searchon=names&suite=all&section=all) of Ubuntu.

For CentOS 6 on x86_64 platform you might also use the optimized version of rspamd with pcre-jit, luajit and hiredis bundled. This also contain gmime 2.6 build compatible with the major centos environment. To use this reporitory you can do the following steps:

	# wget -O /etc/yum.repos.d/rspamd.repo http://rspamd.com/CentOS/6/os/x86_64/rspamd.repo
	# rpm --import http://rspamd.com/vsevolod.pubkey
	# yum update
	# yum install rspamd

### Other operating systems

FreeBSD users can install Rspamd from [ports](http://www.freshports.org/mail/rspamd/).

Users of NetBSD (and other systems with pkgsrc) can use [pkgsrc](http://pkgsrc.se/mail/rspamd).

OSX users can install from [MacPorts](https://trac.macports.org/browser/trunk/dports/mail/rspamd/Portfile).


## Build from sources

You can also build rspamd from the source code. To do that grab the source from [github](https://github.com/vstakhov/rspamd) using `git`:

	git clone --recursive https://github.com/vstakhov/rspamd.git

There is also a mirror of rspamd repository: https://git.rspamd.org/vstakhov/rspamd

Please note that `--recursive` option is essential for building rspamd, since it contains some submodules that must be initialized prior to the build process.

### Build requirements

Rspamd requires several 3-rd party software to build and run:

* [libevent](http://libevent.org/) - asynchronous event library
* [glib2](http://library.gnome.org/devel/glib/) - common purposes library
* [gmime2](http://spruce.sourceforge.net/gmime/) - mime parser
* [Luajit](http://www.luajit.org/) - jit compiler for [lua](http://lua.org) programming language
* [cmake](http://www.cmake.org/) - build system used to configure rspamd
* [sqlite3](http://sqlite.org) - embedded database used to store some data by rspamd
* [hiredis](https://github.com/redis/hiredis) - client library for [redis](http://redis.io) key-value storage

You can either install them from sources or (recommended) install using package manager of your system.

### Build process

To build rspamd we recommend to create a separate build directory:

	$ mkdir rspamd.build
	$ cd rspamd.build
	$ cmake ../rspamd
	$ make
	# make install

Alternatively, you can create a distribution package and use it for build your own packages. Here is an example for
[debian](http://debian.org) GNU Linux OS:

	$ mkdir rspamd.build
	$ cd rspamd.build
	$ cmake ../rspamd
	$ make dist
	$ tar xvf rspamd-<rspamd_version>.tar.xz
	$ cd rspamd-<rspamd_version>
	$ debuild

## Running Rspamd

### Platforms with systemd (Arch, CentOS 7, Debian Jessie, Fedora, openSUSE, SLE)

To enable run on startup:

	systemctl enable rspamd.socket

To start once:

	systemctl start rspamd.socket

Rspamd will be started on-demand, so to simulate this you could run:

	rspamc stat

### Ubuntu, Debian Wheezy

To enable run on startup:
	
	update-rc.d rspamd defaults

To start once:
	
	/etc/init.d/rspamd start

### CentOS 6

To enable run on startup:

	chkconfig rspamd on

To start once:

	/etc/init.d/rspamd start

For information about how to configure different MTA with rspamd, please consider the [following document](https://rspamd.com/doc/integration.html).

## Configuring Rspamd

Though Rspamd's default config aims to be useful for most purposes you may wish to make some adjustments to it to suit your environment/tastes.

There are some different approaches you could take to this which suffer similar drawbacks:

1) Is to modify the stock config files in `/etc/rspamd` directly. Your package manager will not replace the modified config files on upgrade- and may prompt you to merge changes or install these files with an added extension depending on your platform.

2) Is to instead create an `rspamd.conf.local` and/or `rspamd.conf.local.override` in the `/etc/rspamd` directory. What distinguishes these files is the way in which they alter config- `rspamd.conf.local` adds or _merges_ config elements (and is useful for example for setting custom metrics) while `rspamd.conf.local.override` adds or _replaces_ config elements (and is useful for example for configuring workers or RBLs).

### Setting listening interface

Rspamd's normal worker will by default listen on all interfaces on port 11333. If you're running Rspamd on the same machine as your mailer (or whatever will be querying it) you might want to set this to 'localhost' instead.

This is configured in `rspamd.conf` or `rspamd.sysvinit.conf` on Debian Wheezy & Ubuntu. The config to be modified is shown below (`*` should be replaced with whatever address you would prefer to listen on).

    worker {
        bind_socket = "*:11333";
        .include "$CONFDIR/worker-normal.inc"
    }

If you plan to leave this as is you may wish to use a firewall to restrict access to your own machines.

### Setting controller password

Rspamd requires a password when queried from non-trusted IPs except for scanning messages which is unrestricted (the default config trusts the loopback interface). This is configured in `worker-controller.inc`. The config to be modified is shown below (replace 'q1' with your chosen password):

`password = "q1";`

Optionally you may set `enable_password` - if set, data-changing operations (such as training bayes or fuzzy storage) will require this password. For example:

`enable_password = "q2";`

Moreover, you can store encrypted password for better security. To generate such a password just type

	$ rspamd --encrypt-password
	Enter passphrase:
	$1$4mqeynj3st9pb7cgbj6uoyhnyu3cp8d3$59y6xa4mrihaqdw3tf5mtpzg4k7u69ypebc3yba8jdssoh39x16y

Then you can copy this string and store it in the configuration file. Rspamd uses [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) algorithm that makes it very hard to brute-force this password even if it has been compromised.

### Configuring RBLs

Though Rspamd is free to use for any purpose many of the RBLs used in the default configuration aren't & care should be taken to see that your use cases are not infringing. Notes about specific RBLs follow below (please follow the links for details):

[Spamhaus](https://www.spamhaus.org/organization/dnsblusage/) - Commercial use forbidden (see link for definition); Limit of 300k queries or 100k SMTP connections per day

[URIBL](http://uribl.com/about.shtml) - Requires a commercial subscription if 'excessive queries' are sent (numbers unclear).

[SURBL](http://www.surbl.org/usage-policy) - Commercial use forbidden (see link for definition); Limit of 1k users or 250k queries per day

[DNSWL](https://www.dnswl.org/?page_id=9) - Commercial use forbidden (see link for definition); Limit of 100k queries per day

[SpamEatingMonkey](http://spameatingmonkey.com/faq.html#query-limits) - Limit of 100k queries per day or more than 5 queries per second for more than a few minutes

[SORBS](http://www.sorbs.net/general/using.shtml#largesites) - Limit of 100k users or more than 5 messages per second sustained

[Mailspike](http://mailspike.net/usage.html) - Limit of 100k messages or queries per day

[UCEProtect](http://www.uceprotect.net/en/index.php?m=6&s=11) - If you're sending 100k queries or more per day you should use the (free) Rsync service.

These are configured in `modules.conf` in the `rbl{}` and `surbl{}` sections. Detailed documentation for the RBL module is available [here](https://rspamd.com/doc/modules/rbl.html).
