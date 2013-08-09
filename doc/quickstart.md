---
layout: default
title: Rspamd quick start
---

# Rspamd quick start

This guide describes the main procedures to get and start working with rspamd.

## Build requirements

Rspamd requires several 3-rd party software to build and run:
* [libevent](http://www.monkey.org/~provos/libevent/) - asynchronous event library
* [glib2](http://library.gnome.org/devel/glib/) - common purposes library
* [gmime2](http://spruce.sourceforge.net/gmime/) - mime parser
* [Lua](http://www.lua.org/) - extendable scripting language
* [cmake](http://www.cmake.org/) - advanced software build system

You can either install them from sources or (recommended) install using package manager of your system.

### Build process

Building of rspamd is quite a simple procedure:

	cmake .
	make
	make install

After installation binaries, rules, plugins and a sample configuration will be installed in the target directories (prefixed by /usr/local by default). To start working with rspamd you should do several steps:
1. Copy a sample configuration $PREFIX/etc/rspamd.xml.sample to $PREFIX/etc/rspamd.xml
2. Edit rspamd.xml according to your system (described later).
3. Make a directory for rspamd pid file and data (/var/run/rspamd by default) and make rspamd user (nobody by default) as owner of rspamd data directory.
4. Make a directory for rspamd logs (or setup syslog to accept rspamd log messages)
5. Install start script to a proper place (this step is done when installing from FreeBSD ports)
6. Start rspamd using start script

If start script is not suitable for your system (now rspamd shipped with start script for FreeBSD, Debian and RedHat like operational systems) you should write a start script based on your system's documentation.

## Rspamd configuration

Rspamd works well with a sample configuration file, but it requires several changes to make startup successfull:

* Edit *options* section to setup pid file:
{% highlight xml %}
<!-- Options -->
<options>
  <!-- Temporary directory -->
  <tempdir>/tmp</tempdir>
  <!-- Path to pid file -->
  <pidfile>/var/run/rspamd/rspamd.pid</pidfile>

  ...

  <!-- File for saving settings of symbols cache -->
  <cache_file>/var/run/rspamd/symbols.cache</cache_file>
</options>
{% endhighlight %}

* Setup logging (syslog or file):
{% highlight xml %}
<!-- Logging section -->
<logging>
 <level>info</level>
 <type filename="/var/log/rspamd/rspamd.log">file</type>
<!--
 <type facility="local7">syslog</type>
-->
</logging>
{% endhighlight %}

* Setup statistic:

{% highlight xml %}
<classifier type="bayes">
 <tokenizer>osb-text</tokenizer>
 <metric>default</metric>
 <min_tokens>10</min_tokens>
 <statfile>
  <symbol>BAYES_HAM</symbol>
  <size>10M</size>
  <path>/var/run/rspamd/bayes.ham</path>
 </statfile>
 <statfile>
  <symbol>BAYES_SPAM</symbol>
  <size>10M</size>
  <path>/var/run/rspamd/bayes.spam</path>
 </statfile>
</classifier>
{% endhighlight %}

After this initial setup you can run rspamd using start script:

	service rspamd start (for Linux)
	/usr/local/etc/rc.d/rspamd start (for FreeBSD)

Rspamd listens several ports based on configuration. By default the following values are used:
* *:11333 - for scanning messages
* localhost:11334 - for learning messages and managing rspamd
* :11335 (udp) - for fuzzy hashes interface

You can check rspamd status by command:

	$ rspamc stat
