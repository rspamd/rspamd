---
layout: default
title: Downloads
---

# Downloading rspamd

<p><a class="btn btn-primary btn-lg" href="/downloads/rspamd-1.0.4.tar.xz">Download rspamd-1.0.4</a></p>
<p><iframe src="//rspamd.com/github-btn.html?user=vstakhov&repo=rspamd&type=watch&count=true&size=large"
  allowtransparency="true" frameborder="0" scrolling="0" width="170" height="30"></iframe></p>


## Using your OS resources

Rspamd is intended to run on Unix-like operating systems only. FreeBSD users can use ports
collection via [mail/rspamd](http://www.freshports.org/mail/rspamd) for installation.

### Arch, CentOS, Debian, Fedora, openSUSE, SLE, Ubuntu

Also there are pre-built packages at the OpenSUSE build service for debian, fedora, opensuse and
various versions of ubuntu:

<http://software.opensuse.org/download.html?project=home%3Acebka&package=rspamd>

Rspamd is also available in Debian's [testing](https://packages.debian.org/source/testing/rspamd) and [unstable](https://packages.debian.org/source/unstable/rspamd) distributions and the universe repository in [some versions](http://packages.ubuntu.com/search?keywords=rspamd&searchon=names&suite=all&section=all) of Ubuntu.

For CentOS 6 on x86_64 platform you might also use the optimized version of rspamd with pcre-jit, luajit and hiredis bundled. This also contain gmime 2.6 build compatible with the major centos environment. To use this reporitory you can do the following steps:

	# wget -O /etc/yum.repos.d/rspamd.repo http://rspamd.com/CentOS/6/os/x86_64/rspamd.repo
	# rpm --import http://rspamd.com/vsevolod.pubkey
	# yum update
	# yum install rspamd

These packages are also tested on the recent Ubuntu 14.04 LTS. However, you might want to fix `systemd` specific routines 
in `/etc/rspamd/workers.conf` and `/etc/rspamd/logging.conf`.

If you want to check the integrity of your source archive downloaded, then you could use the following [GPG signature](/downloads/rspamd-1.0.4.tar.xz.asc).
This signature can be verified against my [GPG public key](https://rspamd.com/vsevolod.pubkey). 

There is a [guide](https://rspamd.com/doc/quickstart.html) that describes the process of rspamd installation and initial configuration for various operating systems.

## Nightly releases

If you'd like to test the current rspamd version, you might use nightly builds that are currently available for **CentOS 6** and debian based distributives:

- Debian wheezy
- Debian jessie
- Ubuntu precise
- Ubuntu trusty
- Ubuntu vivid

Nightly builds are not as stable as mainline ones but they contain additional features and bugs are fixed very fast when detected.

To use nightly builds on CentOS 6, please follow these instructions:

	wget -O /etc/yum.repos.d/rspamd-nightly.repo http://rspamd.com/CentOS/6/nightly/x86_64/rspamd.repo
	rpm --import http://rspamd.com/CentOS/6/nightly/x86_64/nightly.key
	yum update
	yum install rspamd

To use nightly builds on Debian based distirbutive, do the following (we assume that `codename` is your distributive name):
	
	apt-get install -y lsb-release # optional
	CODENAME=`lsb_release -c -s`
	wget -O- http://rspamd.com/apt/gpg.key | apt-key add -
	echo "deb http://rspamd.com/apt/ $CODENAME main" > /etc/apt/sources.list.d/rspamd.list
	echo "deb-src http://rspamd.com/apt/ $CODENAME main" >> /etc/apt/sources.list.d/rspamd.list
	apt-get update
	apt-get install rspamd

To learn your codename, you could try command `lsb_release -s -c` from the package called `lsb-release`.

## Development resources

Rspamd uses [github](https://github.com) as the main development platform. Should you have any questions
about rspamd development then you can visit:

<https://github.com/vstakhov/rspamd>
