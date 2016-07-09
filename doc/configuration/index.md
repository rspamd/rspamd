---
layout: doc_conf
title: General information
---
# Rspamd configuration

Rspamd uses the Universal Configuration Language (UCL) for its configuration. The UCL format is described in detail in this [document](ucl.html). Rspamd defines several variables and macros to extend
UCL functionality.

## Rspamd variables

- *CONFDIR*: configuration directory for Rspamd, found in `$PREFIX/etc/rspamd/`
- *RUNDIR*: runtime directory to store pidfiles or UNIX sockets
- *DBDIR*: persistent databases directory (used for statistics or symbols cache).
- *LOGDIR*: a directory to store log files
- *PLUGINSDIR*: plugins directory for Lua plugins
- *PREFIX*: basic installation prefix
- *VERSION*: Rspamd version string (e.g. "0.6.6")

## Rspamd specific macros

- *.include_map*: defines a map that is dynamically reloaded and updated if its content has changed. This macro is intended to define dynamic configuration files.

## Rspamd basic configuration

The basic Rspamd configuration is stored in `$CONFDIR/rspamd.conf`. By default, this file looks like this one:

~~~ucl
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

In this file, we read a Lua script placed in `$CONFDIR/lua/rspamd.lua` and load Lua rules from it. Then we include a global [options](options.html) section followed by [logging](logging.html) logging configuration. The [metrics](metrics.html) section defines metric settings, including rule weights and Rspamd actions. The [workers](../workers/index.html) section specifies Rspamd workers settings. [Composites](composites.html) is a utility section that describes composite symbols. Statistical filters are defined in the [statistic](statistic.html) section. Rspamd stores module configurations (for both Lua and internal modules) in the [modules](../modules/index.html) section while modules themselves are loaded from the following portion of the configuration:

~~~ucl
modules {
	path = "$PLUGINSDIR/lua/"
}
~~~

The modules section defines the path or paths of directories or specific files. If a directory is specified then all files with a `.lua` suffix are loaded as lua plugins (the directory path is treated as a `*.lua` shell pattern).

This configuration is not intended to be changed by the user, rather you can include your own configuration options as `.include`s. To redefine symbol weights and actions, it is recommended to use [dynamic configuration](settings.html). Nevertheless, the Rspamd installation script will never overwrite a user's configuration if it exists already. Please read the Rspamd changelog carefully, if you upgrade Rspamd to a new version, for all incompatible configuration changes.
