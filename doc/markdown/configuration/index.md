# rspamd configuration

rspamd uses the Universal Configuration Language (UCL) for its configuration. The UCL format is described in detail in this [document](ucl.md). rspamd defines several variables and macros to extend
UCL functionality.

## rspamd variables

- *CONFDIR*: configuration directory for rspamd, found in `$PREFIX/etc/rspamd/`
- *RUNDIR*: runtime directory to store pidfiles or unix sockets
- *DBDIR*: persistent databases directory (used for statistics or symbols cache).
- *LOGDIR*: a directory to store log files
- *PLUGINSDIR*: plugins directory for lua plugins
- *PREFIX*: basic installation prefix
- *VERSION*: rspamd version string (e.g. "0.6.6")

## rspamd specific macros

- *.include_map*: defines a map that is dynamically reloaded and updated if its content has changed. This macro is intended to define dynamic configuration files.

## rspamd basic configuration

The basic rspamd configuration is stored in `$CONFDIR/rspamd.conf`. By default, this file looks like this one:

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

In this file, we read a lua script placed in `$CONFDIR/lua/rspamd.lua` and load lua rules from it. Then we include a global [options](options.md) section followed by [logging](logging.md) logging configuration. The [metrics](metrics.md) section defines metric settings, including rule weights and rspamd actions. The [workers](../workers/index.md) section specifies rspamd workers settings. [Composites](composites.md) is a utility section that describes composite symbols. Statistical filters are defined in the [statistic](statistic.md) section. rspamd stores module configurations (for both lua and internal modules) in the [modules](../modules/index.md) section while modules themselves are loaded from the following portion of the configuration:

~~~ucl
modules {
	path = "$PLUGINSDIR/lua/"
}
~~~

The modules section defines the path or paths of directories or specific files. If a directory is specified then all files with a `.lua` suffix are loaded as lua plugins (the directory path is treated as a `*.lua` shell pattern).

This configuration is not intended to be changed by the user, rather you can include your own configuration options as `.include`s. To redefine symbol weights and actions, it is recommended to use [dynamic configuration](settings.md). Nevertheless, the rspamd installation script will never overwrite a user's configuration if it exists already. Please read the rspamd changelog carefully, if you upgrade rspamd to a new version, for all incompatible configuration changes.
