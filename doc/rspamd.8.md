% RSPAMD(8) Rspamd User Manual

# NAME

rspamd - main daemon for rapid spam filtering system

# SYNOPSIS

rspamd [*options*]...

rspamd --help

# DESCRIPTION

Rspamd filtering system is designed to be fast, modular and easily scalable system. 
Rspamd core is written in `C` language using event driven processing model. 
Plugins for rspamd can be written in `Lua` programming language.
Rspamd is designed to process connections completely asynchronous and do not block anywhere in code.

# OPTIONS

-f, \--no-fork
:	Do not daemonize main process

-c *path*, \--config=*path*
:	Specify config file(s)

-u *username*, \--user=*username*
:	User to run rspamd as

-g *groupname*, \--group=*groupname*
:	Group to run rspamd as

-p *path*, \--pid=*path*
:	Path to pidfile

-i, \--insecure
:	Ignore running workers as privileged users (insecure)

# EXAMPLES

Run rspamd daemon with default configuration:

	rspamd
	
Run rspamd in foreground with custom configuration:

	rspamd -f -c ~/rspamd.conf
	
Run rspamd specifying user and group:

	rspamd -u rspamd -g rspamd -c /etc/rspamd/rspamd.conf

# SEE ALSO

Rspamd documentation and source codes may be downloaded from
<https://rspamd.com/>.