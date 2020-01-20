#!/bin/sh
# Creates a tarball with the concatenation of a git tree and the submodules.
# Hidden files such as .gitignore are skipped.

# GNU tar
TAR=${2:-"tar"}

if [ $# -lt 1 ] ; then
	echo "Usage: dist.sh <filename> [tar_command]"
	exit 1
fi

FNAME=$1
PREFIX=`basename $FNAME | sed -e 's/\.tar.*$//'`

ALL_TAR=$(mktemp) || { echo "mktemp is missing!"; exit 1; }
TMP_TAR=$(mktemp) || { echo "mktemp is missing!"; exit 1; }
trap 'rm -f "$TMP_TAR" "$ALL_TAR"' EXIT

# Create tarball for main repo contents.
git archive --prefix="$PREFIX/" HEAD ":!.*" ":!**/.*" > "$ALL_TAR"

# Append submodule contents, if any.
export PREFIX TMP_TAR ALL_TAR
git submodule --quiet foreach --recursive \
	'git archive --prefix="$PREFIX/$displaypath/" HEAD ":!.*" ":!**/.*" > "$TMP_TAR";
	 tar Af "$ALL_TAR" "$TMP_TAR"'

xz < "$ALL_TAR" > "$FNAME"
