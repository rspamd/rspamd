#!/bin/sh

# Process command-line arguments
LARG=""
for i in "$@"
do
	LARG="$LARG -a $i"
done

# Call rspamadm lua
rspamadm lua $LARG rspamdgrep.lua
