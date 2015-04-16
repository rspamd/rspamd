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

## Configuration parameters

Here is summary of logging parameters: 

* `type` - Defines logging type (file, console or syslog). For some types mandatory attribute is required:
  - `filename` - path to log file for file logging
  - `facility` - logging facility for syslog
* `level` - Defines loggging level (error, warning, info or debug).
* `log_buffer` - For file and console logging defines buffer size that will be used for logging output.
* `log_urls` - Flag that defines whether all urls in message would be logged. Useful for testing.
* `debug_ip` - List that contains ip addresses for which debugging would be turned on.
* `log_color` - Turn on coloring for log messages. Default: `no`.
