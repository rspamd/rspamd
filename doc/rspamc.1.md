% RSPAMC(1) Rspamd User Manual

# NAME

rspamc - rspamd command line client

# SYNOPSIS

rspamc [*options*] [*command*] [*input-file*]...

rspamc \-\-help

# DESCRIPTION

Rspamc is a simple client for checking messages using rspamd or for learning rspamd by messages.
Rspamc supports the following commands:

* Scan commands:
	* *symbols*: scan message and show symbols (default command)
* Control commands
	* *learn_spam*: learn message as spam
	* *learn_ham*: learn message as ham
	* *fuzzy_add*: add message to fuzzy storage (check `\-f` and `\-w` options for this command)
	* *fuzzy_del*: delete message from fuzzy storage (check `\-f` option for this command)
	* *stat*: show rspamd statistics
	* *stat_reset*: show and reset rspamd statistics (useful for graphs)
	* *counters*: display rspamd symbols statistics
	* *uptime*: show rspamd uptime
	* *add_symbol*: add or modify symbol settings in rspamd
	* *add_action*: add or modify action settings

Control commands that modifies rspamd state are considered as privileged and basically requires a password
to be specified with `\-P` option (see **OPTIONS**, below, for details). 
This depends on a controller's settings and is discussed in `rspamd-workers` page.

`Input files` may be either regular file(s) or a directory to scan. If no files are specified rspamc reads
from the standard input. Controller commands usually does not accept any input, however learn* and fuzzy* commands
requires input. 

# OPTIONS

\-h *host[:port]*, \--connect=*host[:port]*
	Specify host and port
	
\-P *password*, \--password=*password*
	Specify control password
	
-c *name*, \--classifier=*name*
:	Classifier to learn spam or ham (bayes is used by default)

-w *weight*, \--weight=*weight*
:	Weight for fuzzy operations

-f *number*, \--flag=*number*
:	Flag for fuzzy operations

-p, \--pass
:	Pass all filters

-v, \--verbose
:	More verbose output

-i *ip address*, \--ip=*ip address*
:	Emulate that message was received from specified ip address

-u *username*, \--user=*username*
:	Emulate that message was from specified user

-d *user@domain*, \--deliver=*user@domain*
:	Emulate that message is delivered to specified user

-F *user@domain*, \--from=*user@domain*
:	Emulate that message is from specified user

-r *user@domain*, \--rcpt=*user@domain*
:	Emulate that message is for specified user

\--helo=*helo_string*
:	Imitate SMTP HELO passing from MTA

\--hostname=*hostname*
:	Imitate hostname passing from MTA (rspamd assumes that it is verified by MTA)

-t *seconds*, \--timeout=*seconds*
:	Timeout for waiting for a reply

-b *host:port*, \--bind=*host:port*
:	Bind to specified ip address

\--commands
:	List available commands

# RETURN VALUE

On exit rspamc returns `0` if operation was successfull and an error code otherwise.

# EXAMPLES

Check stdin:

	rspamc < some_file

Check files:
	
	rspamc symbols file1 file2 file3
	
Learn files:

	rspamc \-P pass learn_spam file1 file2 file3

Add fuzzy hash to set 2:
	
	rspamc \-P pass \-f 2 \-w 10 fuzzy_add file1 file2
	
Delete fuzzy hash from other server:

	rspamc \-P pass \-h hostname:11334 \-f 2 fuzzy_del file1 file2
	
Get statistics:
	
	rspamc stat

Get uptime:
	
	rspamc uptime

Add custom rule's weight:

	rspamc add_symbol test 1.5
	
Add custom action's weight:

    rspamc add_action reject 7.1
    
# SEE ALSO

Rspamd documentation and source codes may be downloaded from
<https://rspamd.com/>.

[rspamd-workers]: https://rspamd.com/doc/workers/