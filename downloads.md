---
layout: default
title: Downloads
---

# Downloading rspamd

You can download the most recent stable version as source tarball from the following resource:

<p><a class="btn btn-primary btn-lg" href="/downloads/rspamd-1.0.11.tar.xz">Download rspamd-1.0.11</a></p>
<p><iframe src="//rspamd.com/github-btn.html?user=vstakhov&repo=rspamd&type=watch&count=true&size=large"
  allowtransparency="true" frameborder="0" scrolling="0" width="170" height="30"></iframe></p>

# Installing rspamd

The best way to install rspamd is to use the pre-built packages for your operating system. We have prepared packages for many platforms. You have two choices when using packages:

1. Use **stable** branch of packages: those packages are the official rspamd releases which are recommended for production usage.
2. Use **experimental** branch of packages: these packages are less stable and they are generated frequently from the current development branch. Experimental packages usually have more features but might be *sometimes* broken in some points (nevertheless, bugs are usually quickly fixed after detection). 

Rspamd requires **POSIX** environment to run, so it won't likely run on Windows. However, it should work on the vast majority of unix systems, including Linux, BSD (FreeBSD, NetBSD, OpenBSD), OSX and Solaris.

## Rspamd packages

### Arch, CentOS, Debian, Fedora, openSUSE, SLE, Ubuntu

Rspamd project provides packages for some rpm and deb based repositories:

- Debian wheezy (amd64, i386)
- Debian jessie (amd64, i386)
- Ubuntu precise (amd64, i386)
- Ubuntu trusty (amd64, i386)
- Ubuntu vivid (amd64, i386)
- Ubuntu wily (amd64, i386)
- CentOS 6 (amd64), need EPEL
- CentOS 7 (amd64), need EPEL
- Fedora 21 (amd64)
- Fedora 22 (amd64)

#### Installation for rpm based distributions:

Please mention that `CentOS` rpm packages **requires** [EPEL](https://fedoraproject.org/wiki/EPEL) to be installed in your system as many dependencies are missing from the base CentOS repositories. You can learn how to install EPEL from their site: <https://fedoraproject.org/wiki/EPEL>.
`Fedora` packages do not require EPEL or any other third-party repository.

To install rspamd repo, please download the corresponding repository file and the signing key (both repo and all packages are signed with my GPG key). You could use the following commands to install rspamd RPM repository:

    wget -O /etc/yum.repos.d/rspamd.repo http://rspamd.com/rpm-stable/${YOUR_DISTRO}/rspamd.repo
    rpm --import http://rspamd.com/rpm-stable/gpg.key
    yum update
    yum install rspamd

Where `${YOUR_DISTRO}` is the short name of your os (e.g. `centos-7` or `fedora-22`).

For experimental branch packages, download `rpm-experimental` repofile as following:

    wget -O /etc/yum.repos.d/rspamd-experimental.repo http://rspamd.com/rpm/${YOUR_DISTRO}/rspamd-experimental.repo
    rpm --import http://rspamd.com/rpm/gpg.key
    yum update
    yum install rspamd

#### Installation for deb based distributions:



    apt-get install -y lsb-release # optional
    CODENAME=`lsb_release -c -s`
    wget -O- http://rspamd.com/apt-stable/gpg.key | apt-key add -
	echo "deb http://rspamd.com/apt-stable/ $CODENAME main" > /etc/apt/sources.list.d/rspamd.list
	echo "deb-src http://rspamd.com/apt-stable/ $CODENAME main" >> /etc/apt/sources.list.d/rspamd.list
    apt-get update
    apt-get install rspamd

To learn your codename, you could try command `lsb_release -s -c` from the package called `lsb-release`.

For experimental branch replace `apt-stable` with just `apt`:

    apt-get install -y lsb-release # optional
    CODENAME=`lsb_release -c -s`
    wget -O- http://rspamd.com/apt/gpg.key | apt-key add -
	echo "deb http://rspamd.com/apt/ $CODENAME main" > /etc/apt/sources.list.d/rspamd.list
	echo "deb-src http://rspamd.com/apt/ $CODENAME main" >> /etc/apt/sources.list.d/rspamd.list
    apt-get update
    apt-get install rspamd

### Other Linux distributions

For other distributions you could also check [our project on the openSUSE build service](https://software.opensuse.org/download.html?project=home%3Acebka&package=rspamd). Gentoo users can also use the corresponding `portages` for both rspamd and rmilter.

### Debian `official` repos

Rspamd is also available in Debian's [testing](https://packages.debian.org/source/testing/rspamd) and [unstable](https://packages.debian.org/source/unstable/rspamd) distributions and the universe repository in [some versions](http://packages.ubuntu.com/search?keywords=rspamd&searchon=names&suite=all&section=all) of Ubuntu. However, we are looking for an active maintainer for rspamd in these 'official' repos, as now rspamd is terribly outdated there.

Please **DO NOT** use those packages, as they are no longer supported.

### Other operating systems

FreeBSD users can install Rspamd from [ports](http://www.freshports.org/mail/rspamd/).

Users of NetBSD (and other systems with pkgsrc) can use [pkgsrc](http://pkgsrc.se/mail/rspamd).

OSX users can install from [MacPorts](https://trac.macports.org/browser/trunk/dports/mail/rspamd/Portfile).

## Build rspamd from the sources

You can also build rspamd from the source code. To do that grab the source from [github](https://github.com/vstakhov/rspamd) using `git`:

	git clone --recursive https://github.com/vstakhov/rspamd.git

There is also a mirror of rspamd repository: <https://git.rspamd.org/vstakhov/rspamd>

Please note that `--recursive` option is essential for building rspamd, since the repository contains some submodules that must be initialized prior to the build process.

### Build requirements

Rspamd requires several 3-rd party software to build and run:

* [libevent](http://libevent.org/) - asynchronous event library
* [glib2](http://library.gnome.org/devel/glib/) - common purposes library
* [gmime2](http://spruce.sourceforge.net/gmime/) - mime parser
* [Luajit](http://www.luajit.org/) - jit compiler for [lua](http://lua.org) programming language
* [cmake](http://www.cmake.org/) - build system used to configure rspamd
* [sqlite3](http://sqlite.org) - embedded database used to store some data by rspamd
* [hiredis](https://github.com/redis/hiredis) - client library for [redis](http://redis.io) key-value storage
* libmagic - common library for detecting file types

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

## Further reading

Please check the [quickstart guide](/doc/quickstart.html) that describes the subsequent steps to keep rspamd up and running.

## Reporting bugs and other issues

Please check [the support page](support.html)
