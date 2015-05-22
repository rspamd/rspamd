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

There is a [guide](https://rspamd.com/doc/quickstart.html) that describes the process of rspamd installation and initial configuration for various operating systems.

## Development resources

Rspamd uses [github](https://github.com) as the main development platform. Should you have any questions
about rspamd development then you can visit:

<https://github.com/vstakhov/rspamd>
