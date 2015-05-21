---
layout: default
title: Downloads
---

# Downloading rspamd

<p><a class="btn btn-primary btn-lg" href="/downloads/rspamd-0.9.4.tar.xz">Download rspamd-0.9.4</a></p>
<p><iframe src="//rspamd.com/github-btn.html?user=vstakhov&repo=rspamd&type=watch&count=true&size=large"
  allowtransparency="true" frameborder="0" scrolling="0" width="170" height="30"></iframe></p>


## Using your OS resources

Rspamd is intended to run on Unix-like operating systems only. FreeBSD users can use ports
collection via [mail/rspamd](http://www.freshports.org/mail/rspamd) for installation.

[Debian](http://www.debian.org) users can install rspamd directly from the official repositories for
[testing](https://packages.debian.org/source/testing/rspamd) and [unstable](https://packages.debian.org/source/unstable/rspamd) distributions.

These packages are also tested on the recent Ubuntu 14.04 LTS. However, you might want to fix `systemd` specific routines 
in `/etc/rspamd/workers.conf` and `/etc/rspamd/logging.conf`.

Also there are pre-built packages at the OpenSUSE build service for debian, fedora, opensuse and
various versions of ubuntu:

<http://software.opensuse.org/download.html?project=home%3Acebka&package=rspamd>

If you want to check the integrity of your source archive downloaded, then you could use the following [GPG signature](/downloads/rspamd-0.9.4.tar.xz.asc).
This signature can be verified against my [GPG public key](https://rspamd.com/vsevolod.pubkey). 


## Building from the sources

### Build requirements

Rspamd requires several 3-rd party software packages to build and run:

* [libevent](http://libevent.org) - asynchronous event library
* [glib](http://gnome.org) - common purposes library
* [gmime](http://spruce.sourceforge.net/gmime/) - mime parser
* [lua](http://lua.org) - extendable scripting language (version 5.1 should be used)
* [cmake](http://cmake.org) - advanced software build system
* [openssl](http://openssl.org) - generic purposes cryptographic library

If you want additional optimizations of lua scripts then you should consider installation of [luajit](http://luajit.org). This requirement is enabled by default in the upcoming version of rspamd.

You can either install them from sources or (recommended) install using package manager of your system.

### Build process

To build rspamd from the sources please follow these steps:

1. Extract rspamd source archive:

~~~
$ tar xf rspamd-0.9.4.tar.xz
~~~

-OR-

Clone rspamd repository:

~~~
$ git clone --recurse-submodules https://github.com/vstakhov/rspamd.git
~~~

2. Install all dependencies and create a build directory:

~~~
$ mkdir rspamd.build
~~~

3. From rspamd build directory run `cmake` with specifying the path to the source
directory, for example:

~~~
$ cmake ../rspamd
~~~

4. After configure process has finished you can build rspamd using `make`:

~~~
$ make
# make install
~~~

After installation binaries, rules, plugins and a sample configuration will be
installed in the target directories (prefixed by */usr/local* by default).

## Development resources

Rspamd uses [github](https://github.com) as the main development platform. Should you have any questions
about rspamd development then you can visit:

<https://github.com/vstakhov/rspamd>
