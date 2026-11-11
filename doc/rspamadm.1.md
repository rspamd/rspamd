% RSPAMADM(1) Rspamd User Manual

# NAME

rspamadm - rspamd administration utility

# SYNOPSIS

rspamadm [*global_options*] [*command*] [*command_options*]...

# DESCRIPTION

`rspamadm` is a routine to manage rspamd spam filtering system. It is intended to perform
such actions as merging databases, performing configuration tests, encrypting passwords,
signing configurations and so on. You can get a list of available **commands** by running

    rspamadm -l

Also for each command you can check list of available **command_options** by running

    rspamadm help command
    rspamadm command --help

# OPTIONS

-h, \--help
:   Show help message

-v, \--verbose
:   Enable verbose output

-l, \--list-commands
:   List available commands

\--version
:   Show version

\--var=*value*
:   Redefine ucl variable in format `VARIABLE=VALUE`

# COMMAND DISCOVERY

In addition to the built-in commands, `rspamadm` discovers Lua command modules
(`*.lua` files exporting a `handler` function) from the following locations, in
order:

1. The built-in command directory inside rspamd's `lualib` tree.
2. `$CONFDIR/rspamadm.d/*.lua` (a drop-in directory, consistent with `local.d`
   and `modules.local.d`), if it exists.
3. Every directory listed in the colon-separated `RSPAMADM_COMMAND_PATH`
   environment variable (mirrors how `PATH` works).

This lets third-party or premium packages ship `rspamadm` commands without
writing into the rspamd-owned `lualib` tree. Externally loaded commands run with
the same environment as the built-in ones (`rspamd_config`, event base, DNS
resolver) and can `require` Lua libraries reachable through the configured
`lua_path`. If two locations provide a command with the same name, the first one
discovered wins (built-in commands always take precedence).

# ENVIRONMENT

RSPAMADM_COMMAND_PATH
:   A colon-separated list of extra directories to scan for Lua command modules,
    e.g. `RSPAMADM_COMMAND_PATH=/usr/share/rspamd-console/rspamadm`.

# RETURN VALUE

On exit `rspamadm` returns `0` if operation was successful and an error code otherwise.

# EXAMPLES

Get help for pw command:

    rspamadm help pw
    rspamadm pw --help

Encrypt controller's password:

    rspamadm pw encrypt

Merge fuzzy databases:

    rspamadm fuzzy_merge -s data1.sqlite -s data2.sqlite -t dest.sqlite

Perform configuration test:

    rspamadm configtest -c rspamd.conf

Test configuration strictly and redefine some ucl vars:

    rspamadm --var=DBDIR=/tmp configtest -c ./rspamd.conf -s


Dump the processed configuration:

    rspamadm configdump

Dump the processed configuration as JSON string:

    rspamadm configdump -j

Generate a keypair to use for HTTPCrypt encryption:

    rspamadm keypair

# SEE ALSO

Rspamd documentation and source codes may be downloaded from
<https://rspamd.com/>.
