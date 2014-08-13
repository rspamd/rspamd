---
layout: default
title: Downloads
---

# Obtaining rspamd
Rspamd runs on Unix-like operating systems. FreeBSD users can use ports
collection (mail/rspamd) for rspamd installation. Ubuntu users can use launchpad PPA:

<https://launchpad.net/~vsevolod-n/+archive/rspamd>

Also there are pre-built packages at the OpenSUSE build service for debian, fedora, opensuse and
various versions of ubuntu:

<http://software.opensuse.org/download.html?project=home%3Acebka&package=rspamd>

Users of other OSes can use sources to build and install rspamd. The recent version of rspamd is
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

Building of rspamd is simple:


    $ cmake .
    $ make
    # make install


After installation binaries, rules, plugins and a sample configuration will be
installed in the target directories (prefixed by */usr/local* by default). To
start working with rspamd you should do several steps (please note that this is
not applicable to an installation based on packages, as such an installation
have everything ready for using):

1. Edit rspamd.conf according to your system (described
later). 
2. Make a directory for rspamd pid file and data (/var/run/rspamd by
default) and make rspamd user (nobody by default) as the owner of rspamd data
directory. 
3. Make a directory for rspamd logs (or setup syslog to accept
rspamd log messages).
4. Install start script to a proper place.
6. Start rspamd using start script.

If start script is not suitable for your system (now rspamd shipped with start
script for FreeBSD, Debian and RedHat like operational systems) you should
write a start script suitable for your system.
