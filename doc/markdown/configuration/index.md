# Rspamd configuration

Rspamd uses UCL for its configuration. UCL format is described in details in
this [document](ucl.md). Rspamd defines several variables and macros to extend
UCL functionality.

## Table of Contents

* [Options](options.md)
* [Logging](logging.md)
* [Metrics](metrics.md)
* [Composites](composites.md)
* [User settings](settings.md)
* [Statistic configuration](statistic.md)
* [Workers](../workers/index.md)
* [Modules](../modules/index.md)

## Rspamd variables

- *CONFDIR*: configuration directory for rspamd, it is $PREFIX/etc/rspamd/
- *RUNDIR*: runtime directory to store pidfiles or unix sockets
- *DBDIR*: persistent databases directory (used for statistics or symbols cache).
- *LOGDIR*: a directory to store log files
- *PLUGINSDIR*: plugins directory where lua plugins live
- *PREFIX*: basic installation prefix
- *VERSION*: rspamd version string (e.g. "0.6.6")

## Rspamd specific macros

- *.include_map*: defines a map that is dynamically reloaded and updated if its
content has been changed. This macros is intended to define dynamic configuration
parts.

## Rspamd basic configuration

The basic rspamd configuration is stored in $CONFDIR/rspamd.conf. By default, this
file looks like this one:

~~~nginx
lua = "$CONFDIR/lua/rspamd.lua"

.include "$CONFDIR/options.conf"
.include "$CONFDIR/logging.conf"
.include "$CONFDIR/metrics.conf"
.include "$CONFDIR/workers.conf"
.include "$CONFDIR/composites.conf"

.include "$CONFDIR/statistic.conf"

.include "$CONFDIR/modules.conf"

modules {
	path = "$PLUGINSDIR/lua/"
}
~~~

In this file, we open lua script placed in `$CONFDIR/lua/rspamd.lua` and load
lua rules from it. Then we include global [options](options.md) section followed
by [logging](logging.md) logging configuration. [Metrics](metrics.md) section defines
metric settings, including rules weights and rspamd actions. [Workers](workers.md)
section specifies rspamd workers settings. [Composites](composites.md) is an utility
section that describes composite symbols. Statistical filters are defined in 
[statistic](statistic.md) section. Rspamd stores modules configuration (for both lua
and internal modules) in [modules](../modules/index.md) section while modules itself are
loaded from the following portion of configuration:

~~~nginx
modules {
	path = "$PLUGINSDIR/lua/"
}
~~~

This section defines one or single path to either directories or specific files.
If directory is used then all files with suffix `.lua` are loaded as lua plugins
(it is `*.lua` shell pattern therefore).

This configuration is not intended to be changed by user, but you can include your
own configuration in further. To redefine symbols weight and actions rspamd encourages
to use [dynamic configuration](settings.md). Nevertheless, rspamd installation
script will never rewrite user's configuration if it exists already. So please 
read ChangeLog carefully if you upgrade rspamd to a new version for all incompatible
configuration changes.
