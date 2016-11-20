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
.include "$CONFDIR/common.conf"

options {
    .include "$CONFDIR/options.inc"
    .include(try=true; priority=1,duplicate=merge) "$LOCAL_CONFDIR/local.d/options.inc"
    .include(try=true; priority=10) "$LOCAL_CONFDIR/override.d/options.inc"
}

logging {
    type = "console";
    systemd = true;
    .include "$CONFDIR/logging.inc"
    .include(try=true; priority=1,duplicate=merge) "$LOCAL_CONFDIR/local.d/logging.inc"
    .include(try=true; priority=10) "$LOCAL_CONFDIR/override.d/logging.inc"
}

worker {
    bind_socket = "*:11333";
    .include "$CONFDIR/worker-normal.inc"
    .include(try=true; priority=1,duplicate=merge) "$LOCAL_CONFDIR/local.d/worker-normal.inc"
    .include(try=true; priority=10) "$LOCAL_CONFDIR/override.d/worker-normal.inc"
}

worker {
    bind_socket = "localhost:11334";
    .include "$CONFDIR/worker-controller.inc"
    .include(try=true; priority=1,duplicate=merge) "$LOCAL_CONFDIR/local.d/worker-controller.inc"
    .include(try=true; priority=10) "$LOCAL_CONFDIR/override.d/worker-controller.inc"
}
~~~

In `common.conf`, we read a Lua script placed in `$RULESDIR/rspamd.lua` and load Lua rules from it. Then we include a global [options](options.html) section followed by [logging](logging.html) logging configuration. The [metrics.conf](metrics.html) file defines metric settings, including rule weights and Rspamd actions. The [workers](../workers/index.html) section specifies Rspamd workers settings. [Composites.conf](composites.html) describes composite symbols. Statistical filters are defined in [statistics.conf](statistic.html). Rspamd stores module configurations (for both Lua and internal modules) in  [modules.d](../modules/index.html) section while modules themselves are loaded from the following portion of `common.conf`:

~~~ucl
modules {
	path = "$PLUGINSDIR/lua/"
}
~~~

The modules section defines the path or paths of directories or specific files. If a directory is specified then all files with a `.lua` suffix are loaded as lua plugins (the directory path is treated as a `*.lua` shell pattern).

This configuration is not intended to be changed by the user, rather it should be overridden in site-specific configuration files- see the [quickstart]({{ site.baseurl }}/doc/quickstart.html#configuring-rspamd) for details. Nevertheless, packaging will generally never overwrite configuration files on upgrade if they have been touched by the user. Please read the [migration notes]({{ site.baseurl }}/doc/migration.html) carefully if you upgrade Rspamd to a new version for all incompatible configuration changes.
