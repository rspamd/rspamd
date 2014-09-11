[![Build Status](https://travis-ci.org/vstakhov/rspamd.png)](https://travis-ci.org/vstakhov/rspamd)

References
==========

* Home site: <https://rspamd.com>

Description
===========

Rspamd is a complex spam filter that allows to estimate messages by a number of
rules including regular expression, statistical analysis and custom services,
such as URL black lists. Each message is analysed by rspamd and got a *spam
score*. 

According to this spam score and user's settings rspamd recommends to apply an
action for this message to MTA, for example to pass, to reject or to add spam
header. Rspamd has own unique features among spam filters: 

* event driven architecture allowing to process many messages at a time;
* flexible syntax of rules allowing to write rules in lua language;
* a lot of plugins and rules shipped with rspamd distribution;
* highly optimized mail processing;
* advanced statistic;

All these features allow rspamd to process messages fast and demonstrate a
suitable spam filtering. 

Installation
============

Rspamd runs on a Unix like operational systems. FreeBSD users can use ports
collection (mail/rspamd) for rspamd installation. Ubuntu users can use launchpad PPA:

<https://launchpad.net/~vsevolod-n/+archive/rspamd>

Users of other OSes should use sources to build and install rspamd. Alternatively you could check the OpenSUSE build system for packages suitable for your environment:

<http://software.opensuse.org/download.html?project=home%3Acebka&package=rspamd>

There are packages for debian and CentOS/RHEL distribution. Debian users could
use *debuild* utility to create the binary packages of rspamd. CentOS/RHEL
users could use spec file and other RedHat specific stuff from **centos**
folder.  The users of other systems could try to adopt some package or just to
build from sources.

Build requirements
------------------

Rspamd requires several 3-rd party software to build and run:

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

Further Actions
===============

You can improve the quality of rspamd filtering by learning its statistical module. The easiest
way to do it is to use rspamc client (you can setup a custom email alias to
pipe messages to rspamc)

~~~
$ rspamc -P 'q1' learn_spam [ file1 [file2 [...]]]
$ rspamc -P 'q1' learn_ham [ file1 [file2 [...]]]
~~~

Note: you should consider to change default controller's password `q1` to a more secure
one specified in the controller section of configuration.

Also a system administrator might want to customize rule's weights or actions
thresholds. This can be done easily by editing `metrics.conf`
configuration file.

For writing new rules you can examine the main [rspamd documentation](https://rspamd.com/doc/) and [lua api](https://rspamd.com/doc/lua/)
guide and reference.
