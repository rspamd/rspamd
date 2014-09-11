---
layout: default
title: Downloads
---

# Obtaining rspamd

Rspamd uses [github](https://github.com) as the main development platform. Should you have any questions
about rspamd development then you can visit:

<https://github.com/vstakhov/rspamd>

Rspamd is intended to run on Unix-like operating systems only. FreeBSD users can use ports
collection (mail/rspamd) for rspamd installation. Ubuntu users can use launchpad PPA:

<https://launchpad.net/~vsevolod-n/+archive/rspamd>

Also there are pre-built packages at the OpenSUSE build service for debian, fedora, opensuse and
various versions of ubuntu:

<http://software.opensuse.org/download.html?project=home%3Acebka&package=rspamd>

Users of other OSes can use sources to build and install rspamd. The most recent stable version of rspamd is
0.6.10.

<p><a class="btn btn-primary" href="/downloads/rspamd-0.6.10.tar.xz">Download rspamd-0.6.10</a></p>

[Signature](/downloads/rspamd-0.6.10.tar.gz.asc)

[My GPG key](https://rspamd.com/vsevolod.pubkey)

There are packages for debian and CentOS/RHEL distribution. Debian users could
use `debuild` utility to create the binary packages of rspamd. CentOS/RHEL
users could use spec file and other RedHat specific stuff from `centos`
folder.  The users of other systems could try to adopt some package or just to
build from sources.

Build requirements
------------------

Rspamd requires several 3-rd party software packages to build and run:

* libevent - asynchronous event library
* glib - common purposes library
* gmime - mime parser
* lua - extendable scripting language
* cmake - advanced software build system 

You can either install them from sources or (recommended) install using package manager of your system.

Build process
-------------

To build rspamd from the sources please follow these steps:

1. Clone rspamd repository:

    $ git clone --recurse-submodules https://github.com/vstakhov/rspamd.git

2. Install all dependencies and create a build directory:

    $ mkdir rspamd.build

3. From rspamd build directory run `cmake` with specifying the path to the source
directory, for example:

    $ cmake ../rspamd

4. After configure process has finished you can build rspamd using `make`:

    $ make
    # make install

After installation binaries, rules, plugins and a sample configuration will be
installed in the target directories (prefixed by */usr/local* by default).
