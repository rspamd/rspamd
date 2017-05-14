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
