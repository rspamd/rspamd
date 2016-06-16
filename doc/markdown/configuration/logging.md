# rspamd logging settings

## Introduction
rspamd has a number of logging options. Firstly, there are three types of log output that are supported: console logging (just output log messages to console), file logging (output log messages to file) and logging via syslog. It is also possible to restrict logging to a specific level:

* `error` - log only critical errors
* `warning` - log errors and warnings
* `info` - log all non-debug messages
* `debug` - log all including debug messages (huge amount of logging)

It is possible to turn on debug messages for specific ip addresses. This can be useful for testing. For each logging type there are special mandatory parameters: log facility for syslog (read `syslog(3)` man page for details about facilities), log file for file logging. Also, file logging may be buffered for performance. To reduce logging noise, rspamd detects sequential matching log messages and replaces them with a total number of repeats:

	#81123(fuzzy): May 11 19:41:54 rspamd file_log_function: Last message repeated 155 times
	#81123(fuzzy): May 11 19:41:54 rspamd process_write_command: fuzzy hash was successfully added

## Unique id

From version 1.0, rspamd logs contain a unique id for each logging message. This allows finding relevant messages quickly. Moreover, there is now a `module` definition: for example, `task` or `cfg` modules. Here is a quick example of how it works: imagine that we have an incoming task for some message. Then you'd see something like this in the logs:

    2015-09-02 16:41:59 #45015(normal) <ed2abb>; task; accept_socket: accepted connection from ::1 port 52895
    2015-09-02 16:41:59 #45015(normal) <ed2abb>; task; rspamd_message_parse: loaded message; id: <F66099EE-BCAB-4D4F-A4FC-7C15A6686397@FreeBSD.org>; queue-id: <undef>

So the tag is `ed2abb` in this case. All subsequent processing related to this task will have the same tag. It is enabled not only on the `task` module, but also others, such as the `spf` or `lua` modules. For other modules, such as `cfg`, the tag is generated statically using a specific characteristic, for example the configuration file checksum.

## Configuration parameters

Here is summary of logging parameters:

- `type` - Defines logging type (file, console or syslog). For some types mandatory attributes may be required:
    + `filename` - path to log file for file logging
    + `facility` - logging facility for syslog
- `level` - Defines logging level (error, warning, info or debug).
- `log_buffer` - For file and console logging defines buffer size that will be used for logging output.
- `log_urls` - Flag that defines whether all urls in message should be logged. Useful for testing.
- `debug_ip` - List that contains ip addresses for which debugging should be turned on.
- `log_color` - Turn on coloring for log messages. Default: `no`.
- `debug_modules` - A list of modules that are enabled for debugging. The following modules are available here:
    + `task` - task messages
    + `cfg` - configuration messages
    + `symcache` - messages from symbols cache
    + `fuzzy_backend` - messages from fuzzy backend
    + `lua` - messages from lua code
    + `spf` - messages from spf module
    + `dkim` - messages from dkim module
    + `main` - messages from the main process
    + `dns` - messages from DNS resolver
    + `map` - messages from maps in rspamd
    + `logger` - messages from the logger itself

### Log format

rspamd supports a custom log format when writing information about a message to the log. (This feature is supported since version 1.1.) The format string looks as follows:


	log_format =<< EOD
	id: <$mid>,$if_qid{ qid: <$>,}$if_ip{ ip: $,}$if_user{ user: $,}$if_smtp_from{ from: <$>,}
	(default: $is_spam ($action): [$scores] [$symbols]),
	len: $len, time: $time_real real,
	$time_virtual virtual, dns req: $dns_req
	EOD

Newlines are replaced with spaces. Both text and variables are supported in the log format line. Each variable can have an optional `if_` prefix, which will log only if it is triggered. Moreover, each variable can have an optional body value, where `$` is replaced with the variable value (as many times as it is found in the body, e.g. `$var{$$$$}` will be replaced with the variable's name repeated 4 times).

rspamd supports the following variables:

- `mid` - message id
- `qid` - queue id
- `ip` - from IP
- `user` - authenticated user
- `smtp_from` - envelope from (or MIME from if SMTP from is absent)
- `mime_from` - MIME from
- `smtp_rcpt` - envelope rcpt (or MIME from if SMTP from is absent) - the first recipient
- `mime_rcpt` - MIME rcpt - the first recipient
- `smtp_rcpts` - envelope rcpts - all recipients
- `mime_rcpts` - MIME rcpts - all recipients
- `len` - length of essage
- `is_spam` - a one-letter rating of spammyness: `T` for spam, `F` for ham and `S` for skipped messages
- `action` - default metric action
- `symbols` - list of all symbols
- `time_real` - real time of task processing
- `time_virtual` - CPU time of task processing
- `dns_req` - number of DNS requests
- `lua` - custom lua script, e.g:

~~~lua
	$lua{
		return function(task) 
			return 'text parts: ' .. tostring(#task:get_text_parts()) end
	}
~~~
