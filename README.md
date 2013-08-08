[![Build Status](https://travis-ci.org/vstakhov/rspamd.png)](https://travis-ci.org/vstakhov/rspamd)

REFERENCES
==========

* Home site: <http://rspamd.com>
* Downloads: <https://bitbucket.org/vstakhov/rspamd/downloads>
* Wiki: <https://bitbucket.org/vstakhov/rspamd/wiki/>

DESCRIPTION
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

INSTALLATION
============

Rspamd runs on a Unix like operational systems. FreeBSD users can use ports
collection (mail/rspamd) for rspamd installation. Ubuntu users can use launchpad PPA:

<https://launchpad.net/~vsevolod-n/+archive/rspamd>

Users of other OSes should use sources to build and install rspamd. You can
obtain rspamd sources at the bitbucket download page:

<https://bitbucket.org/vstakhov/rspamd/downloads>

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

Building of rspamd is simple:


    $ cmake .
    $ make
    # make install


After installation binaries, rules, plugins and a sample configuration will be
installed in the target directories (prefixed by */usr/local* by default). To
start working with rspamd you should do several steps (please note that this is
not applicable to an installation based on packages, as such an installation
have everything ready for using):

1. Copy a sample configuration $PREFIX/etc/rspamd.xml.sample to
$PREFIX/etc/rspamd.xml
2. Edit rspamd.xml according to your system (described
later). 
3. Make a directory for rspamd pid file and data (/var/run/rspamd by
default) and make rspamd user (nobody by default) as the owner of rspamd data
directory. 
4. Make a directory for rspamd logs (or setup syslog to accept
rspamd log messages).
5. Install start script to a proper place.
6. Start rspamd using start script.

If start script is not suitable for your system (now rspamd shipped with start
script for FreeBSD, Debian and RedHat like operational systems) you should
write a start script suitable for your system.

FURTHER ACTIONS
===============

You can improve quality of rspamd by learning its statistic module. The easiest
way to do it is to use rspamc client (you can setup a custom email alias to
pipe messages to rspamc)

    $ rspamc -P 'q1' -c bayes learn_spam [ file1 [file2 [...]]]
    $ rspamc -P 'q1' -c bayes learn_ham [ file1 [file2 [...]]]

Note: you should consider to change default controller's password 'q1' to yours
one specified in the controller section of configuration.

Also a system administrator may want to customize rule's weights or actions
thresholds. This can be easily done by editing metric section in the
configuration file.

For writing new rules you can examine the main rspamd documentation and lua api
guide and reference.
