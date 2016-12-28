---
layout: downloads
title: Downloads
---

<!--# Downloading rspamd->

<!-- download button with tooltip
<p><a class="btn btn-primary btn-lg" href="{{ site.baseurl }}/downloads/rspamd-1.3.1.tar.xz" data-toggle="tooltip" data-placement="right" title="Download the most recent stable version as source tarball">Download rspamd-1.3.1</a></p>
<!-- github button >
<p><iframe src="{{ site.baseurl }}/github-btn.html?user=vstakhov&repo=rspamd&type=watch&count=true&size=large"
  allowtransparency="true" frameborder="0" scrolling="0" width="170" height="30"></iframe></p-->

## Rspamd packages
<!-- Tab navigation -->
<div class="col-xs-12">
    <ul class="nav nav-tabs nav-justified" role="tablist">
        <li role="presentation" class="active">
            <a href="#system1" aria-controls="system1" role="tab" data-toggle="tab"><img src="img/redhat.png" width="20"><span class="myHidden-sm">&nbsp;Fedora/CentOS</span></a>
        </li>
        <li role="presentation">
            <a href="#system2" aria-controls="system2" role="tab" data-toggle="tab"><img src="img/Ubuntu.png" width="20"><span class="myHidden-sm">&nbsp;Debian/Ubuntu</span></a>
        </li>
        <li role="presentation">
            <a href="#system3" aria-controls="system3" role="tab" data-toggle="tab"><img src="img/linux.png" width="20"><span class="myHidden-sm">&nbsp;Other&nbsp;Linux</span></a>
        </li>
        <li role="presentation">
            <a href="#system4" aria-controls="system4" role="tab" data-toggle="tab"><img src="img/freebsd.png" width="20"><span class="myHidden-sm">&nbsp;BSD</span></a>
        </li>
        <li role="presentation">
            <a href="#system5" aria-controls="system5" role="tab" data-toggle="tab"><img src="img/octocat.png" width="20"><span class="myHidden-sm">&nbsp;Build&nbsp;rspamd</span></a>
        </li>
    </ul>
    <!-- Tab - pane content -->
    <div class="tab-content">
        <div role="tabpanel" class="tab-pane fade in active" id="system1">
            <h3>CentOS, Fedora</h3>
<div markdown="1">
Supported distributions:

- **CentOS 6** (amd64), need EPEL
- **CentOS 7** (amd64), need EPEL
- **Fedora 21** (amd64)
- **Fedora 22** (amd64)
- **Fedora 23** (amd64)

Please note that `CentOS` rpm packages **requires** [EPEL](https://fedoraproject.org/wiki/EPEL) to be installed in your system as many dependencies are missing from the base CentOS repositories. You can learn how to install EPEL from their site: <https://fedoraproject.org/wiki/EPEL>.
`Fedora` packages do not require EPEL or any other third-party repository.

To install rspamd repo, please download the corresponding repository file and the signing key (both repo and all packages are signed with my GPG key). You could use the following commands to install rspamd <a class="undecor" href="#stableSys1">stable<sup>1</sup></a> RPM repository:

    curl http://rspamd.com/rpm-stable/${YOUR_DISTRO}/rspamd.repo > /etc/yum.repos.d/rspamd.repo
    rpm --import http://rspamd.com/rpm-stable/gpg.key
    yum update
    yum install rspamd

Where `${YOUR_DISTRO}` is the short name of your os (e.g. `centos-7` or `fedora-22`).

For <a class="undecor" href="#experimentalSys1">experimental<sup>2</sup></a> branch packages, download `rpm-experimental` repofile as following:

    curl http://rspamd.com/rpm-stable/${YOUR_DISTRO}/rspamd-experimental.repo > /etc/yum.repos.d/rspamd-experimental.repo
    rpm --import http://rspamd.com/rpm/gpg.key
    yum update
    yum install rspamd    

</div>
<hr>
<p class="myFootnote" id="stableSys1">1. Use STABLE branch of packages: those packages are the official rspamd releases which are recommended for production usage.</p>
<p class="myFootnote" id="experimentalSys1">2. Use EXPERIMENTAL branch of packages: these packages are less stable and they are generated frequently from the current development branch. Experimental packages usually have more features but might be SOMETIMES broken in some points (nevertheless, bugs are usually quickly fixed after detection).</p>
        </div>
        <div role="tabpanel" class="tab-pane fade" id="system2">
            <h3>Debian and Ubuntu Linux</h3>
<div markdown="1">

Rspamd supports the following .deb based distributives:

- **Debian wheezy** (amd64, i386)
- **Debian jessie** (amd64, i386)
- **Debian sid** (amd64, i386)
- **Ubuntu precise** (amd64, i386)
- **Ubuntu trusty** (amd64, i386)
- **Ubuntu wily** (amd64, i386)
- **Ubuntu xenial** (amd64, i386)

To install the rspamd <a class="undecor" href="#stableSys2">stable<sup>1</sup></a> apt repository, please use the following commands:

    apt-get install -y lsb-release wget # optional
    CODENAME=`lsb_release -c -s`
    wget -O- https://rspamd.com/apt-stable/gpg.key | apt-key add -
    echo "deb http://rspamd.com/apt-stable/ $CODENAME main" > /etc/apt/sources.list.d/rspamd.list
    echo "deb-src http://rspamd.com/apt-stable/ $CODENAME main" >> /etc/apt/sources.list.d/rspamd.list
    apt-get update
    apt-get --no-install-recommends install rspamd

To obtain your distributive's codename, you could use the command `lsb_release -s -c` from the package called `lsb-release`.

For <a class="undecor" href="#experimentalSys2">experimental<sup>2</sup></a> branch replace `apt-stable` with just `apt`:

    apt-get install -y lsb-release wget # optional
    CODENAME=`lsb_release -c -s`
    wget -O- https://rspamd.com/apt/gpg.key | apt-key add -
    echo "deb http://rspamd.com/apt/ $CODENAME main" > /etc/apt/sources.list.d/rspamd.list
    echo "deb-src http://rspamd.com/apt/ $CODENAME main" >> /etc/apt/sources.list.d/rspamd.list
    apt-get update
    apt-get --no-install-recommends install rspamd

Check [quick start]({{ site.baseurl }}/doc/quickstart.html#rspamd-installation) for further steps.

### Debian `official` repos

Rspamd is also available in some versions of Debian and Ubuntu. However, we are looking for an active maintainer for rspamd in these 'official' repos, as now rspamd is terribly outdated there.

Please **DO NOT** use those packages, as they are no longer supported.

</div>
<hr>
<p class="myFootnote" id="stableSys2">1. Use STABLE branch of packages: those packages are the official rspamd releases which are recommended for production usage.</p>
<p class="myFootnote" id="experimentalSys2">2. Use EXPERIMENTAL branch of packages: these packages are less stable and they are generated frequently from the current development branch. Experimental packages usually have more features but might be SOMETIMES broken in some points (nevertheless, bugs are usually quickly fixed after detection).</p>
        </div>
        <div role="tabpanel" class="tab-pane fade" id="system3">
            <h3>Other Linux</h3>
<div markdown="1">
Rspamd is also supported on the following Linux distributions:

- **Alpine Linux**
- **Arch Linux**
- **Gentoo Linux**
- **Void Linux**

### Alpine Linux
Rspamd is available in the [testing repository](https://pkgs.alpinelinux.org/package/edge/testing/x86_64/rspamd)

### Arch Linux
Rspamd is available in the [AUR](https://aur.archlinux.org/packages/rspamd)

### Gentoo Linux
Ebuilds for Gentoo Linux users are available in the main [Gentoo Portage repository](https://packages.gentoo.org/packages/mail-filter/rspamd).

### Void Linux
Packages for Void Linux are available in the main [package repository](https://github.com/voidlinux/void-packages/tree/master/srcpkgs/rspamd).

</div>
        </div>
        <div role="tabpanel" class="tab-pane fade" id="system4">
            <h3>BSD systems</h3>
<div markdown="1">
Rspamd has been ported to the following BSD like operating systems:

- **FreeBSD**
- **NetBSD**
- **OpenBSD**
- **OSX** (using MacPorts)

FreeBSD users can install Rspamd from [ports](http://www.freshports.org/mail/rspamd/) or use the experimental line of packages by [rspamd-devel](http://www.freshports.org/mail/rspamd-devel/) port.

Users of NetBSD (and other systems with pkgsrc) can use [pkgsrc](http://pkgsrc.se/mail/rspamd).

OpenBSD users can use [ports](http://openports.se/mail/rspamd).

OSX users can install from [MacPorts](https://trac.macports.org/browser/trunk/dports/mail/rspamd/Portfile).
</div>
        </div>
        <div role="tabpanel" class="tab-pane fade" id="system5">
            <h3>Build rspamd from the sources</h3>
<div markdown="1">

If there are no packages for your system or you want custom build options you can also build rspamd from the source code. To do that grab the source from [github](https://github.com/vstakhov/rspamd) using `git`:

	git clone --recursive https://github.com/vstakhov/rspamd.git

There is also a mirror of rspamd repository: <https://git.rspamd.org/vstakhov/rspamd>

Please note that `--recursive` option is essential for building rspamd, since the repository contains some submodules that must be initialized prior to the build process.

### Build requirements

Rspamd requires several 3-rd party software to build and run:

* [openssl](https://www.openssl.org/) - cryptography and SSL/TLS Toolkit
* [libevent](http://libevent.org/) - asynchronous event library
* [glib2](http://library.gnome.org/devel/glib/) - common purposes library
* [gmime2](http://spruce.sourceforge.net/gmime/) - mime parser
* [Luajit](http://www.luajit.org/) - jit compiler for [lua](http://lua.org) programming language
* [cmake](http://www.cmake.org/) - build system used to configure rspamd
* [sqlite3](http://sqlite.org) - embedded database used to store some data by rspamd
* [hiredis](https://github.com/redis/hiredis) - client library for [redis](http://redis.io) key-value storage
* [libmagic](http://www.darwinsys.com/file/) - common library for detecting file types

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
</div>
        </div>
    </div>
</div>

## Further reading

Please check the [quickstart guide]({{ site.baseurl }}/doc/quickstart.html) that describes the subsequent steps to keep rspamd up and running. The most frequently asked questions are listed in the [FAQ]({{ site.baseurl }}/doc/faq.html).

## Reporting bugs and other issues

Please check [the support page](support.html)
