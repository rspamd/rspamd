# Rspamd logging settings

## Introduction
Rspamd has a number of logging variants. First of all there are three types of logs that are supported by rspamd: console loggging (just output log messages to console), file logging (output log messages to file) and logging via syslog. Also it is possible to filter logging to specific level:

* `error` - log only critical errors
* `warning` - log errors and warnings
* `info` - log all non-debug messages
* `debug` - log all including debug messages (huge amount of logging) 

Also it is possible to turn on debug messages for specific ip addresses. This ability is usefull for testing. For each logging type there are special mandatory parameters: log facility for syslog (read `syslog(3)` manual page for details about facilities), log file for file logging. Also file logging may be buffered for speeding up. For reducing logging noise rspamd detects for sequential identic log messages and replace them with total number of repeats:

	#81123(fuzzy): May 11 19:41:54 rspamd file_log_function: Last message repeated 155 times
	#81123(fuzzy): May 11 19:41:54 rspamd process_write_command: fuzzy hash was successfully added

## Unique id

From version 1.0, rspamd logs now contain unique id for each logging message. That allows to find the relevant messages quickly and filter everything else. Moreover, there is `module` definition now, for example `task` or `cfg` modules. Here is a quick example of how it works: let's imagine that we have an incoming task for some message. Then you'd see something like this in the logs:

    2015-09-02 16:41:59 #45015(normal) <ed2abb>; task; accept_socket: accepted connection from ::1 port 52895
    2015-09-02 16:41:59 #45015(normal) <ed2abb>; task; rspamd_message_parse: loaded message; id: <F66099EE-BCAB-4D4F-A4FC-7C15A6686397@FreeBSD.org>; queue-id: <undef>

So the tag is `ed2abb` in this case. Afterwards, all processing related to this task will have the same tag. It includes not merely `task` module, but also other modules, such as `spf` or `lua` logger.
For other modules, such as `cfg` the tag is generated statically, using some specific characteristic, for example configuration file checksum.

## Configuration parameters

Here is summary of logging parameters: 

- `type` - Defines logging type (file, console or syslog). For some types mandatory attribute is required:
    + `filename` - path to log file for file logging
    + `facility` - logging facility for syslog
- `level` - Defines loggging level (error, warning, info or debug).
- `log_buffer` - For file and console logging defines buffer size that will be used for logging output.
- `log_urls` - Flag that defines whether all urls in message would be logged. Useful for testing.
- `debug_ip` - List that contains ip addresses for which debugging would be turned on.
- `log_color` - Turn on coloring for log messages. Default: `no`.
- `debug_modules` - A list of modules that are enabled for debugging. Now the following modules are available here:
    + `task` - task messages
    + `cfg` - configuration messages
    + `symcache` - messages from symbols cache
    + `sqlite` - messages from sqlite backends
    + `lua` - messages from lua code
    + `spf` - messages from spf module
    + `dkim` - messages from dkim module
    + `main` - messages from the main process
    + `dns` - messages from DNS resolver
    + `map` - messages from maps in rspamd
    + `logger` - messages from the logger itself
